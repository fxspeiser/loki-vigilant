#!/bin/bash
# Build the RPM package from the repo source.
# Run from the repo root: ./rpm/build-rpm.sh
#
# Requires: rpmbuild (install via: sudo dnf install rpm-build)

set -euo pipefail

cd "$(dirname "$0")/.."
REPO_ROOT="$(pwd)"

NAME="loki-vigilant"
VERSION="$(grep '^Version:' rpm/loki-vigilant.spec | awk '{print $2}')"
TARBALL="${NAME}-${VERSION}"

echo "Building ${NAME}-${VERSION} RPM..."

# Create build tree
BUILD_DIR="$(mktemp -d)"
SOURCES_DIR="${BUILD_DIR}/SOURCES"
mkdir -p "${SOURCES_DIR}"

# Create source tarball — exclude private/runtime files
TAR_DIR="${BUILD_DIR}/${TARBALL}"
mkdir -p "${TAR_DIR}"

# Copy only distributable files
cp -r app.py requirements.txt run.sh setup.sh agent-setup.sh LICENSE README.md "${TAR_DIR}/"
mkdir -p "${TAR_DIR}/backend"
cp backend/*.py "${TAR_DIR}/backend/"
mkdir -p "${TAR_DIR}/frontend/templates" "${TAR_DIR}/frontend/static"
cp frontend/templates/*.html "${TAR_DIR}/frontend/templates/"
cp frontend/static/*.js "${TAR_DIR}/frontend/static/"
cp frontend/static/*.css "${TAR_DIR}/frontend/static/"

# Create tarball
tar -czf "${SOURCES_DIR}/${TARBALL}.tar.gz" -C "${BUILD_DIR}" "${TARBALL}"

# Build RPM
rpmbuild \
    --define "_topdir ${BUILD_DIR}" \
    --define "_sourcedir ${SOURCES_DIR}" \
    -ba rpm/loki-vigilant.spec

# Copy output
mkdir -p "${REPO_ROOT}/dist"
find "${BUILD_DIR}/RPMS" -name '*.rpm' -exec cp {} "${REPO_ROOT}/dist/" \;
find "${BUILD_DIR}/SRPMS" -name '*.rpm' -exec cp {} "${REPO_ROOT}/dist/" \;

echo ""
echo "RPM packages built in dist/:"
ls -lh "${REPO_ROOT}/dist/"*.rpm 2>/dev/null

# Cleanup
rm -rf "${BUILD_DIR}"
