#!/usr/bin/env bash
# Build Cerberus RPM packages.
#
# Usage:
#   ./packaging/rpm/build-rpm.sh                      # build from current tree
#   ./packaging/rpm/build-rpm.sh --mock               # build inside mock (clean chroot)
#   ./packaging/rpm/build-rpm.sh --eif <path-to-eif>  # ALSO build the OPT-IN
#                                                     # cerberus-signer-eif package
#
# --eif bundles a prebuilt, per-deployment EIF into an optional
# cerberus-signer-eif RPM. That RPM carries the KMS-encrypted CA key and the
# PCR0-pinned CA public key, so it is per-deployment and per-architecture — ship
# it only over an operator-controlled channel, never a public repo. --eif needs
# a local build; it is incompatible with --mock's clean chroot.
#
# Prerequisites:
#   dnf install rpm-build rpmdevtools golang make    # Fedora / RHEL / Amazon Linux 2023
#   yum install rpm-build rpmdevtools golang make    # Amazon Linux 2 / RHEL 7
set -euo pipefail

# --- Parse arguments -------------------------------------------------------
MOCK=0
EIF_FILE=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --mock)  MOCK=1; shift ;;
        --eif)
            [[ $# -ge 2 ]] || { echo "ERROR: --eif requires a path argument" >&2; exit 2; }
            EIF_FILE="$2"; shift 2 ;;
        --eif=*) EIF_FILE="${1#--eif=}"; shift ;;
        -h|--help) awk 'NR>1 && /^#/{sub(/^# ?/,""); print; next} NR>1{exit}' "$0"; exit 0 ;;
        *)
            echo "Unknown argument: $1" >&2
            echo "Usage: $0 [--mock] [--eif <path-to-eif>]" >&2
            exit 2 ;;
    esac
done

EXTRA_DEFINES=()
if [[ -n "${EIF_FILE}" ]]; then
    if [[ "${MOCK}" -eq 1 ]]; then
        echo "ERROR: --eif is incompatible with --mock." >&2
        echo "  The EIF is a per-deployment artifact built on a trusted host; bundling it" >&2
        echo "  requires a local (non-chroot) rpmbuild. Re-run without --mock." >&2
        exit 2
    fi
    if [[ ! -f "${EIF_FILE}" ]]; then
        echo "ERROR: EIF file not found: ${EIF_FILE}" >&2
        exit 2
    fi
    # Absolutize: %install reads this path directly from the build host.
    EIF_FILE="$(cd "$(dirname "${EIF_FILE}")" && pwd)/$(basename "${EIF_FILE}")"
    EXTRA_DEFINES+=(--define "eif_file ${EIF_FILE}")
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
VERSION="$(tr -d '[:space:]' < "${PROJECT_ROOT}/VERSION")"
PKG_NAME="cerberus"
TARBALL="${PKG_NAME}-${VERSION}"

echo "==> Building ${PKG_NAME} ${VERSION} RPM"

# Set up rpmbuild tree.
RPMBUILD_DIR="${PROJECT_ROOT}/rpmbuild"
mkdir -p "${RPMBUILD_DIR}"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

# Create the source tarball from the working tree.
echo "==> Creating source tarball..."
STAGING_DIR=$(mktemp -d)
trap 'rm -rf "${STAGING_DIR}"' EXIT

mkdir -p "${STAGING_DIR}/${TARBALL}"
# Use git archive if available, otherwise fall back to rsync.
if git -C "${PROJECT_ROOT}" rev-parse --is-inside-work-tree &>/dev/null; then
    git -C "${PROJECT_ROOT}" archive --format=tar HEAD \
        | tar -x -C "${STAGING_DIR}/${TARBALL}"
    # Include untracked packaging files that may not be committed yet.
    cp -a "${PROJECT_ROOT}/packaging" "${STAGING_DIR}/${TARBALL}/packaging"
    cp -a "${PROJECT_ROOT}/VERSION" "${STAGING_DIR}/${TARBALL}/VERSION"
else
    rsync -a --exclude='.git' --exclude='rpmbuild' \
        "${PROJECT_ROOT}/" "${STAGING_DIR}/${TARBALL}/"
fi

tar -czf "${RPMBUILD_DIR}/SOURCES/${TARBALL}.tar.gz" \
    -C "${STAGING_DIR}" "${TARBALL}"

# Copy spec file.
cp "${SCRIPT_DIR}/cerberus.spec" "${RPMBUILD_DIR}/SPECS/"

# Build the RPM.
if [[ "${MOCK}" -eq 1 ]]; then
    echo "==> Building SRPM for mock..."
    rpmbuild \
        --define "_topdir ${RPMBUILD_DIR}" \
        --define "rpm_version ${VERSION}" \
        -bs "${RPMBUILD_DIR}/SPECS/cerberus.spec"

    SRPM=$(find "${RPMBUILD_DIR}/SRPMS" -name '*.src.rpm' | head -1)
    echo "==> Building in mock chroot..."
    mock --rebuild "${SRPM}"
else
    if [[ -n "${EIF_FILE}" ]]; then
        echo "==> Bundling EIF into the opt-in cerberus-signer-eif package: ${EIF_FILE}"
        echo "    WARNING: this RPM carries the KMS-encrypted CA key + PCR0-pinned public key."
        echo "             It is per-deployment; publish only to an operator-controlled channel."
    fi
    echo "==> Building RPM locally..."
    rpmbuild \
        --define "_topdir ${RPMBUILD_DIR}" \
        --define "rpm_version ${VERSION}" \
        "${EXTRA_DEFINES[@]+"${EXTRA_DEFINES[@]}"}" \
        -ba "${RPMBUILD_DIR}/SPECS/cerberus.spec"
fi

echo ""
echo "==> Build complete. Packages:"
find "${RPMBUILD_DIR}/RPMS" -name '*.rpm' 2>/dev/null | sort
find "${RPMBUILD_DIR}/SRPMS" -name '*.rpm' 2>/dev/null | sort
