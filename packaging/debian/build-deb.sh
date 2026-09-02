#!/usr/bin/env bash
# Build Cerberus Debian packages.
#
# Usage:
#   ./packaging/debian/build-deb.sh                      # build from current tree
#   ./packaging/debian/build-deb.sh --eif <path-to-eif>  # bundle THIS EIF
#   ./packaging/debian/build-deb.sh --no-eif             # never build the EIF package
#
# The cerberus-signer-eif package is produced automatically when the working
# tree holds CA key material -- ssh-cert-signer/ca_key.enc and ca_key.pub, the
# two files the EIF is built from. A tree without them (CI, upstream) is
# unaffected. --eif names an EIF explicitly and skips detection; --no-eif opts
# out. See packaging/eif-detect.sh.
#
# The supported entry point (analogous to build-rpm.sh / build-arch.sh): it
# stages a source snapshot from the working tree, injects the version from
# VERSION into debian/changelog, and runs dpkg-buildpackage. The package uses the
# "3.0 (native)" source format, so no separate upstream tarball is needed.
#
# --eif bundles a prebuilt, per-deployment EIF into an optional
# cerberus-signer-eif package (built under the pkg.cerberus.eif build profile).
# That package carries the KMS-encrypted CA key and the PCR0-pinned CA public
# key, so it is per-deployment and per-architecture — ship it only over an
# operator-controlled channel, never a public repo.
#
# Prerequisites:
#   apt-get install build-essential debhelper dpkg-dev fakeroot
#   Go >= 1.26 on PATH (newer than the distro golang-go; use the golang:1.26
#   image or a manually installed toolchain).
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

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
VERSION="$(tr -d '[:space:]' < "${PROJECT_ROOT}/VERSION")"
PKG_NAME="cerberus"
STAGE_NAME="${PKG_NAME}-${VERSION}"

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
    # Absolutize: debian/rules reads this path directly from its build dir.
    EIF_FILE="$(cd "$(dirname "${EIF_FILE}")" && pwd)/$(basename "${EIF_FILE}")"
fi

echo "==> Building ${PKG_NAME} ${VERSION} Debian packages"

# Throwaway build tree (gitignored). The .debs land directly in debbuild/.
DEBBUILD_DIR="${PROJECT_ROOT}/debbuild"
rm -rf "${DEBBUILD_DIR}"
mkdir -p "${DEBBUILD_DIR}/${STAGE_NAME}"
STAGING="${DEBBUILD_DIR}/${STAGE_NAME}"

echo "==> Staging source snapshot..."
if git -C "${PROJECT_ROOT}" rev-parse --is-inside-work-tree &>/dev/null; then
    git -C "${PROJECT_ROOT}" archive --format=tar HEAD | tar -x -C "${STAGING}"
    # Overlay the working-tree packaging/ so uncommitted or untracked packaging
    # files (e.g. packaging/debian/* before it is committed) are included. Copy
    # the CONTENTS ("/.") into the existing directory to avoid a packaging/
    # packaging/ nesting that would hide them.
    mkdir -p "${STAGING}/packaging"
    cp -a "${PROJECT_ROOT}/packaging/." "${STAGING}/packaging/"
    cp -a "${PROJECT_ROOT}/VERSION" "${STAGING}/VERSION"
else
    rsync -a --exclude='.git' --exclude='debbuild' --exclude='rpmbuild' --exclude='archbuild' \
        "${PROJECT_ROOT}/" "${STAGING}/"
fi

# Install the debian/ packaging dir at the source root and pin the changelog
# version from VERSION so it never drifts from the RPM/Arch version.
cp -a "${SCRIPT_DIR}/." "${STAGING}/debian/"
chmod +x "${STAGING}/debian/rules"
sed -i "1s/^${PKG_NAME} (.*)/${PKG_NAME} (${VERSION})/" "${STAGING}/debian/changelog"

echo "==> Running dpkg-buildpackage..."
BUILD_ENV=()
BUILD_ARGS=(-b -us -uc)
if [[ -n "${EIF_FILE}" ]]; then
    echo "    Bundling EIF into the cerberus-signer-eif package: ${EIF_FILE}"
    cerberus_eif_warn
    BUILD_ENV=(DEB_BUILD_PROFILES="pkg.cerberus.eif" CERBERUS_EIF_FILE="${EIF_FILE}")
    BUILD_ARGS+=(--build-profiles=pkg.cerberus.eif)
fi
(
    cd "${STAGING}"
    env "${BUILD_ENV[@]}" dpkg-buildpackage "${BUILD_ARGS[@]}"
)

# Keep the PCR measurements with the packages they describe.
cerberus_save_pcr_manifest "${EIF_PCR_MANIFEST}" "${DEBBUILD_DIR}"

echo ""
echo "==> Build complete. Packages:"
find "${DEBBUILD_DIR}" -maxdepth 1 -name '*.deb' 2>/dev/null | sort
find "${DEBBUILD_DIR}" -maxdepth 1 -name 'pcr-manifest-*.json' 2>/dev/null | sort
