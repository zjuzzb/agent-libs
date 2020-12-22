#!/bin/bash
#usage install-zlib.sh <directory> <version> <url> <parallelism> <cmake dir>

set -exo pipefail

DEPENDENCIES_DIR=$1
VERSION=$2
DEPENDENCIES_URL=$3
MAKE_JOBS=$4
CMAKE_DIRECTORY=$5

cd $DEPENDENCIES_DIR
wget $DEPENDENCIES_URL/benchmark-$VERSION.zip
unzip benchmark-$VERSION.zip
cd benchmark-$VERSION
mkdir build
cd build
$CMAKE_DIRECTORY/bin/cmake -DBENCHMARK_ENABLE_GTEST_TESTS=OFF -DCMAKE_BUILD_TYPE=Release ..
make -j $MAKE_JOBS

