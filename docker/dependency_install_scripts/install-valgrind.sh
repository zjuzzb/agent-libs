#!/bin/bash
#usage install-valgrind.sh <directory> <version> <url> <parallelism>

set -exo pipefail

DEPENDENCIES_DIR=$1
VERSION=$2
DEPENDENCIES_URL=$3
MAKE_JOBS=$4

cd $DEPENDENCIES_DIR
wget $DEPENDENCIES_URL/valgrind-$VERSION.tar.bz2
tar -xjf valgrind-$VERSION.tar.bz2
cd valgrind-$VERSION
./configure
make -j $MAKE_JOBS
make -j $MAKE_JOBS install
