#!/bin/bash
#usage install-libyaml.sh <directory> <version> <url> <parallelism>

set -exo pipefail

DEPENDENCIES_DIR=$1
VERSION=$2
DEPENDENCIES_URL=$3
MAKE_JOBS=$4

cd $DEPENDENCIES_DIR
wget $DEPENDENCIES_URL/libyaml-$VERSION.tar.gz
tar -xzf libyaml-$VERSION.tar.gz
cd libyaml-$VERSION
./bootstrap && ./configure --prefix=$DEPENDENCIES_DIR/libyaml-$VERSION/target
make -j $MAKE_JOBS
make -j $MAKE_JOBS install
