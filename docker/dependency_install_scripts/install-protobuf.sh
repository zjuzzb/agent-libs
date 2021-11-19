#!/bin/bash
#usage install-protobuf.sh <directory> <version> <url> <parallelism> <zlib dir>

set -exo pipefail

DEPENDENCIES_DIR=$1
VERSION=$2
DEPENDENCIES_URL=$3
MAKE_JOBS=$4
ZLIB_DIRECTORY=$5

cd $DEPENDENCIES_DIR
wget $DEPENDENCIES_URL/protobuf-cpp-$VERSION.tar.gz
tar -xzf protobuf-cpp-$VERSION.tar.gz
cd protobuf-$VERSION

CPPFLAGS=-I$ZLIB_DIRECTORY LDFLAGS=-L$ZLIB_DIRECTORY ./configure --with-zlib --prefix=$DEPENDENCIES_DIR/protobuf-$VERSION/target

# Increase ulimit before running the make on s390x.
# Otherwise, during the make, the protobuf-test fails with a stack overflow.
ARCH=$(uname -m)
if [[ "$ARCH" == "s390x" ]]; then
    ulimit -S -s 16384 || true
fi

make -j $MAKE_JOBS
make -j $MAKE_JOBS check
make -j $MAKE_JOBS install
