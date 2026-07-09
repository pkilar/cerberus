#!/usr/bin/env bash
# Build Cerberus Arch Linux packages.
#
# Usage:
#   ./packaging/arch/build-arch.sh                      # build from current tree
#   ./packaging/arch/build-arch.sh --eif <path-to-eif>  # ALSO build the OPT-IN
#                                                       # cerberus-signer-eif package
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
while [[ $# -gt 0 ]]; do
    case "$1" in
        --eif)
            [[ $# -ge 2 ]] || { echo "ERROR: --eif requires a path argument" >&2; exit 2; }
            EIF_FILE="$2"; shift 2 ;;
        --eif=*) EIF_FILE="${1#--eif=}"; shift ;;
        -h|--help) awk 'NR>1 && /^#/{sub(/^# ?/,""); print; next} NR>1{exit}' "$0"; exit 0 ;;
        *)
            echo "Unknown argument: $1" >&2
            echo "Usage: $0 [--eif <path-to-eif>]" >&2
            exit 2 ;;
    esac
done

if [[ -n "${EIF_FILE}" ]]; then
    if [[ ! -f "${EIF_FILE}" ]]; then
        echo "ERROR: EIF file not found: ${EIF_FILE}" >&2
        exit 2
    fi
    # Absolutize: package_cerberus-signer-eif reads this path directly.
    EIF_FILE="$(cd "$(dirname "${EIF_FILE}")" && pwd)/$(basename "${EIF_FILE}")"
fi

if [[ "$(id -u)" -eq 0 ]]; then
    echo "ERROR: makepkg refuses to run as root. Run this as a regular user." >&2
    exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
VERSION="$(tr -d '[:space:]' < "${PROJECT_ROOT}/VERSION")"
PKG_BASE="cerberus"
TARBALL="${PKG_BASE}-${VERSION}"

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
    echo "    Bundling EIF into the opt-in cerberus-signer-eif package: ${EIF_FILE}"
    echo "    WARNING: this package carries the KMS-encrypted CA key + PCR0-pinned"
    echo "             public key. It is per-deployment; publish only to an"
    echo "             operator-controlled channel."
fi
(
    cd "${ARCHBUILD_DIR}"
    CERBERUS_EIF_FILE="${EIF_FILE}" makepkg --force --noconfirm --clean
)

echo ""
echo "==> Build complete. Packages:"
find "${ARCHBUILD_DIR}" -maxdepth 1 -name '*.pkg.tar.*' 2>/dev/null | sort
