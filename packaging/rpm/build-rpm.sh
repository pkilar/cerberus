#!/usr/bin/env bash
# Build Cerberus RPM packages.
#
# Usage:
#   ./packaging/rpm/build-rpm.sh              # build from current tree
#   ./packaging/rpm/build-rpm.sh --mock       # build inside mock (clean chroot)
#
# Prerequisites:
#   dnf install rpm-build rpmdevtools golang make    # Fedora / RHEL / Amazon Linux 2023
#   yum install rpm-build rpmdevtools golang make    # Amazon Linux 2 / RHEL 7
set -euo pipefail

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
if [[ "${1:-}" == "--mock" ]]; then
    echo "==> Building SRPM for mock..."
    rpmbuild \
        --define "_topdir ${RPMBUILD_DIR}" \
        --define "rpm_version ${VERSION}" \
        -bs "${RPMBUILD_DIR}/SPECS/cerberus.spec"

    SRPM=$(find "${RPMBUILD_DIR}/SRPMS" -name '*.src.rpm' | head -1)
    echo "==> Building in mock chroot..."
    mock --rebuild "${SRPM}"
else
    echo "==> Building RPM locally..."
    rpmbuild \
        --define "_topdir ${RPMBUILD_DIR}" \
        --define "rpm_version ${VERSION}" \
        -ba "${RPMBUILD_DIR}/SPECS/cerberus.spec"
fi

echo ""
echo "==> Build complete. Packages:"
find "${RPMBUILD_DIR}/RPMS" -name '*.rpm' 2>/dev/null | sort
find "${RPMBUILD_DIR}/SRPMS" -name '*.rpm' 2>/dev/null | sort
