#!/bin/bash
#usage install-jq.sh <directory> <version> <url> <parallelism>

set -exo pipefail

DEPENDENCIES_DIR=$1
VERSION=$2
DEPENDENCIES_URL=$3
MAKE_JOBS=$4

cd $DEPENDENCIES_DIR
wget $DEPENDENCIES_URL/jq-$VERSION.tar.gz
tar -xzf jq-$VERSION.tar.gz
wget -O jq-1.5-fix-tokenadd.patch https://github.com/stedolan/jq/commit/8eb1367ca44e772963e704a700ef72ae2e12babd.patch
cd jq-$VERSION
patch < ../jq-1.5-fix-tokenadd.patch
./configure --disable-maintainer-mode --enable-all-static --disable-dependency-tracking
make LDFLAGS=-all-static -j $MAKE_JOBS

