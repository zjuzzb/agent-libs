#!/bin/bash
#usage install-lua.sh <directory> <version> <url> <parallelism>

set -exo pipefail

DEPENDENCIES_DIR=$1
VERSION=$2
DEPENDENCIES_URL=$3
MAKE_JOBS=$4

cd $DEPENDENCIES_DIR
wget $DEPENDENCIES_URL/lua-$VERSION.tar.gz
tar -xzf lua-$VERSION.tar.gz
cd lua-$VERSION
make -j $MAKE_JOBS linux
