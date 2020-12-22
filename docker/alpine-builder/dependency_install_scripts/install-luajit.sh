#!/bin/bash
#usage install-luajit.sh <directory> <version> <url> <parallelism>

set -exo pipefail

DEPENDENCIES_DIR=$1
VERSION=$2
DEPENDENCIES_URL=$3
MAKE_JOBS=$4

cd $DEPENDENCIES_DIR
wget $DEPENDENCIES_URL/LuaJIT-$VERSION.tar.gz
tar -xzf LuaJIT-$VERSION.tar.gz
cd LuaJIT-$VERSION
make -j $MAKE_JOBS
