#!/bin/bash
#usage install-gperftools.sh <directory> <version> <url> <parallelism>

set -exo pipefail

DEPENDENCIES_DIR=$1
VERSION=$2
DEPENDENCIES_URL=$3
MAKE_JOBS=$4

cd $DEPENDENCIES_DIR
wget $DEPENDENCIES_URL/gperftools-$VERSION.tar.gz
tar xfz gperftools-2.5.tar.gz
cd gperftools-$VERSION
./configure --prefix=$DEPENDENCIES_DIR/gperftools-$VERSION/target --enable-emergency-malloc --disable-libunwind
make -j $MAKE_JOBS
make -j $MAKE_JOBS install
