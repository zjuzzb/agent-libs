#!/bin/bash
#usage install-cmake.sh <directory> <version> <url> <parallelism>

set -exo pipefail

DEPENDENCIES_DIR=$1
VERSION=$2
DEPENDENCIES_URL=$3
MAKE_JOBS=$4

cd $DEPENDENCIES_DIR
wget $DEPENDENCIES_URL/cmake-$VERSION.tar.gz
tar -xzf cmake-$VERSION.tar.gz
cd cmake-$VERSION
./bootstrap
make -j $MAKE_JOBS
