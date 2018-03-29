#!/bin/bash

set -e -o pipefail

# Build RPMs, populating a directory structure that indicates the OS release.
# NOTE: This expects to run in a CentOS or RHEL environment, preferrably one of the versity
# rpm-build Docker containers.

OS_RELEASE=$(grep -oE '[0-9]+\.[0-9]+\.[0-9]+' /etc/redhat-release)
echo "OS RELEASE: $OS_RELEASE"

make rpm

rpm_dist="rpms/$OS_RELEASE"
rm -fvr "$rpm_dist"
mkdir -p "$rpm_dist"

cp -v rpmbuild/RPMS/x86_64/kmod-scoutfs*.rpm "$rpm_dist/"
