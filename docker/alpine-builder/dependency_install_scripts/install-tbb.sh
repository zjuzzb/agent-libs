#!/bin/bash
#usage install-tbb.sh <directory> <version> <url> <parallelism>

set -exo pipefail

DEPENDENCIES_DIR=$1
VERSION=$2
DEPENDENCIES_URL=$3
MAKE_JOBS=$4

cd $DEPENDENCIES_DIR
wget $DEPENDENCIES_URL/tbb-$VERSION.tar.gz
tar -xzf tbb-$VERSION.tar.gz
cd tbb-$VERSION
make tbb_build_dir=${DEPENDENCIES_DIR}/tbb-${VERSION}/build tbb_build_prefix=lib extra_inc=big_iron.inc -j $MAKE_JOBS

