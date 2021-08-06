#!/bin/bash
#usage install-cares.sh <directory> <version> <url> <parallelism>

set -exo pipefail

DEPENDENCIES_DIR=$1
VERSION=$2
DEPENDENCIES_URL=$3
MAKE_JOBS=$4

cd $DEPENDENCIES_DIR
wget $DEPENDENCIES_URL/c-ares-$VERSION.tar.gz
tar -xzf c-ares-$VERSION.tar.gz
cd c-ares-$VERSION
./configure --prefix=$DEPENDENCIES_DIR/c-ares-$VERSION/target
make -j $MAKE_JOBS install

