#!/bin/bash
#usage install-postgres.sh <directory> <version> <url> <parallelism>

set -exo pipefail

DEPENDENCIES_DIR=$1
VERSION=$2
DEPENDENCIES_URL=$3
MAKE_JOBS=$4

cd $DEPENDENCIES_DIR
wget $DEPENDENCIES_URL/postgresql-$VERSION.tar.bz2
tar xfj postgresql-$VERSION.tar.bz2
cd postgresql-$VERSION
./configure --prefix=$DEPENDENCIES_DIR/postgresql-$VERSION/target --without-readline --without-zlib
make -j $MAKE_JOBS
make -j $MAKE_JOBS -C src/bin install
make -j $MAKE_JOBS -C src/include install
make -j $MAKE_JOBS -C src/interfaces install
