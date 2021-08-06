#!/bin/bash
#usage install-zlib.sh <directory> <version> <url> <parallelism>

set -exo pipefail

DEPENDENCIES_DIR=$1
VERSION=$2
DEPENDENCIES_URL=$3
MAKE_JOBS=$4

cd $DEPENDENCIES_DIR
wget $DEPENDENCIES_URL/openssl-$VERSION.tar.gz
tar -xzf openssl-$VERSION.tar.gz
cd openssl-$VERSION
./config shared --prefix=$DEPENDENCIES_DIR/openssl-$VERSION/target
make install
