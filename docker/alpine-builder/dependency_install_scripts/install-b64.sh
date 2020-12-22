#!/bin/bash
#usage install-b64.sh <directory> <version> <url> <parallelism>

set -exo pipefail

DEPENDENCIES_DIR=$1
VERSION=$2
DEPENDENCIES_URL=$3
MAKE_JOBS=$4

cd $DEPENDENCIES_DIR
wget $DEPENDENCIES_URL/libb64-$VERSION.src.zip
unzip libb64-$VERSION.src.zip
cd libb64-$VERSION
make -j $MAKE_JOBS
