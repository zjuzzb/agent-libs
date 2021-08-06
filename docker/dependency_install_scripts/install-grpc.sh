#!/bin/bash
#usage install-grpc.sh <directory> <version> <url> <parallelism> <zlib dir> <protobuf dir> <openssl dir> <cares dir>

set -exo pipefail

DEPENDENCIES_DIR=$1
VERSION=$2
DEPENDENCIES_URL=$3
MAKE_JOBS=$4
ZLIB_DIRECTORY=$5
PROTOBUF_DIRECTORY=$6
OPENSSL_DIRECTORY=$7
CARES_DIRECTORY=$8

cd $DEPENDENCIES_DIR
wget $DEPENDENCIES_URL/grpc-$VERSION.tar.gz
tar -xzf grpc-$VERSION.tar.gz
rm -rf grpc-$VERSION/third_party/zlib
ln -s $ZLIB_DIRECTORY grpc-$VERSION/third_party/zlib
cd grpc-$VERSION

# Normally, grpc wants to use its own protobuf library, which it
# expects to get via git submodules. It mostly has support for using
# a "system" protobuf/openssl instead, using pkg-config. The Makefile
# does require one small change to properly set LDFLAGS to the
# protobuf lib path returned by pkg-config. Hence the patch.
wget $DEPENDENCIES_URL/grpc-1.1.4-Makefile.patch
patch < grpc-1.1.4-Makefile.patch

HAS_SYSTEM_ZLIB=false LDFLAGS=-static PATH=$PROTOBUF_DIRECTORY/target/bin:$PATH PKG_CONFIG_PATH=$OPENSSL_DIRECTORY:$PROTOBUF_DIRECTORY:$CARES_DIRECTORY make -j $MAKE_JOBS grpc_cpp_plugin static_cxx static_c

