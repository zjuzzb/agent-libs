#!/bin/bash
#usage install-python.sh <directory> <version> <url> <parallelism> <zlib dir> <openssl dir>

set -exo pipefail

DEPENDENCIES_DIR=$1
VERSION=$2
DEPENDENCIES_URL=$3
MAKE_JOBS=$4
ZLIB_DIR=$5
OPENSSL_DIR=$6

cd $DEPENDENCIES_DIR
wget $DEPENDENCIES_URL/Python-$VERSION.tgz
tar xfz Python-$VERSION.tgz
cd Python-$VERSION
echo "zlib zlibmodule.c -I${ZLIB_DIR}/ -L${ZLIB_DIR}/ -lz" >> Modules/Setup.dist
./configure CPPFLAGS="-DUSE_SSL -I${OPENSSL_DIR}/target/include" LDFLAGS="-L${OPENSSL_DIR}/target/lib -Wl,-rpath=${OPENSSL_DIR}/target/lib" --prefix=$DEPENDENCIES_DIR/Python-$VERSION/target --with-ensurepip=install --enable-unicode=ucs4
make -j $MAKE_JOBS
make -j $MAKE_JOBS install
