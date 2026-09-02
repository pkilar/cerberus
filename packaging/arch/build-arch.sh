#!/usr/bin/env bash
# Build Cerberus Arch Linux packages.
#
# Usage:
#   ./packaging/arch/build-arch.sh                      # build from current tree
#   ./packaging/arch/build-arch.sh --eif <path-to-eif>  # bundle THIS EIF
#   ./packaging/arch/build-arch.sh --no-eif             # never build the EIF package
#
# The cerberus-signer-eif package is produced automatically when the working
# tree holds CA key material -- ssh-cert-signer/ca_key.enc and ca_key.pub, the
# two files the EIF is built from. A tree without them (CI, upstream) is
# unaffected. --eif names an EIF explicitly and skips detection; --no-eif opts
# out. See packaging/eif-detect.sh.
#
# This is the supported entry point (analogous to build-rpm.sh): it stages a
# source tarball from the working tree, injects the version from VERSION into
# the PKGBUILD, and runs makepkg in a throwaway ./archbuild directory.
#
# --eif bundles a prebuilt, per-deployment EIF into an optional
# cerberus-signer-eif package. That package carries the KMS-encrypted CA key and
# the PCR0-pinned CA public key, so it is per-deployment and per-architecture —
# ship it only over an operator-controlled channel, never a public repo.
#
# Prerequisites:
#   pacman -S --needed base-devel go          # makepkg + Go toolchain
#   makepkg must not be run as root.
set -euo pipefail

# --- Parse arguments -------------------------------------------------------
EIF_FILE=""
EIF_PCR_MANIFEST=""
NO_EIF=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --no-eif) NO_EIF=1; shift ;;
        --eif)
            [[ $# -ge 2 ]] || { echo "ERROR: --eif requires a path argument" >&2; exit 2; }
            EIF_FILE="$2"; shift 2 ;;
        --eif=*) EIF_FILE="${1#--eif=}"; shift ;;
        -h|--help) awk 'NR>1 && /^#/{sub(/^# ?/,""); print; next} NR>1{exit}' "$0"; exit 0 ;;
        *)
            echo "Unknown argument: $1" >&2
            echo "Usage: $0 [--eif <path-to-eif>] [--no-eif]" >&2
            exit 2 ;;
    esac
done

if [[ "$(id -u)" -eq 0 ]]; then
    echo "ERROR: makepkg refuses to run as root. Run this as a regular user." >&2
    exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
VERSION="$(tr -d '[:space:]' < "${PROJECT_ROOT}/VERSION")"
PKG_BASE="cerberus"
TARBALL="${PKG_BASE}-${VERSION}"

# shellcheck source=../eif-detect.sh
. "${PROJECT_ROOT}/packaging/eif-detect.sh"

# An explicit --eif wins; otherwise let the CA key material decide.
if [[ -z "${EIF_FILE}" && "${NO_EIF}" -eq 0 ]]; then
    cerberus_eif_autodetect "${PROJECT_ROOT}" || exit 2
fi

if [[ -n "${EIF_FILE}" ]]; then
    if [[ ! -f "${EIF_FILE}" ]]; then
        echo "ERROR: EIF file not found: ${EIF_FILE}" >&2
        exit 2
    fi
    # Absolutize: package_cerberus-signer-eif reads this path directly.
    EIF_FILE="$(cd "$(dirname "${EIF_FILE}")" && pwd)/$(basename "${EIF_FILE}")"
fi

echo "==> Building ${PKG_BASE} ${VERSION} Arch package"

# Set up a throwaway build tree (gitignored).
ARCHBUILD_DIR="${PROJECT_ROOT}/archbuild"
rm -rf "${ARCHBUILD_DIR}"
mkdir -p "${ARCHBUILD_DIR}"

# Create the source tarball from the working tree — same approach as
# build-rpm.sh so both packagings build from an identical snapshot.
echo "==> Creating source tarball..."
STAGING_DIR=$(mktemp -d)
trap 'rm -rf "${STAGING_DIR}"' EXIT

mkdir -p "${STAGING_DIR}/${TARBALL}"
if git -C "${PROJECT_ROOT}" rev-parse --is-inside-work-tree &>/dev/null; then
    git -C "${PROJECT_ROOT}" archive --format=tar HEAD \
        | tar -x -C "${STAGING_DIR}/${TARBALL}"
    # Overlay the working-tree packaging/ so uncommitted or untracked packaging
    # files (e.g. packaging/arch/* before it is committed) are included. Copy the
    # CONTENTS ("/.") into the existing directory rather than the directory
    # itself, which would nest as packaging/packaging/ and hide those files.
    mkdir -p "${STAGING_DIR}/${TARBALL}/packaging"
    cp -a "${PROJECT_ROOT}/packaging/." "${STAGING_DIR}/${TARBALL}/packaging/"
    cp -a "${PROJECT_ROOT}/VERSION" "${STAGING_DIR}/${TARBALL}/VERSION"
else
    rsync -a --exclude='.git' --exclude='archbuild' --exclude='rpmbuild' \
        "${PROJECT_ROOT}/" "${STAGING_DIR}/${TARBALL}/"
fi

tar -czf "${ARCHBUILD_DIR}/${TARBALL}.tar.gz" -C "${STAGING_DIR}" "${TARBALL}"

# Stage PKGBUILD + .install scriptlets (makepkg reads install= from the build
# dir), then pin pkgver from VERSION so it never drifts from the RPM version.
cp "${SCRIPT_DIR}/PKGBUILD" "${ARCHBUILD_DIR}/"
cp "${SCRIPT_DIR}"/*.install "${ARCHBUILD_DIR}/"
sed -i "s/^pkgver=.*/pkgver=${VERSION}/" "${ARCHBUILD_DIR}/PKGBUILD"

echo "==> Running makepkg..."
if [[ -n "${EIF_FILE}" ]]; then
    echo "    Bundling EIF into the cerberus-signer-eif package: ${EIF_FILE}"
    cerberus_eif_warn
fi
(
    cd "${ARCHBUILD_DIR}"
    CERBERUS_EIF_FILE="${EIF_FILE}" makepkg --force --noconfirm --clean
)

# Keep the PCR measurements with the packages they describe.
cerberus_save_pcr_manifest "${EIF_PCR_MANIFEST}" "${ARCHBUILD_DIR}"

echo ""
echo "==> Build complete. Packages:"
find "${ARCHBUILD_DIR}" -maxdepth 1 -name '*.pkg.tar.*' 2>/dev/null | sort
find "${ARCHBUILD_DIR}" -maxdepth 1 -name 'pcr-manifest-*.json' 2>/dev/null | sort
