#!/bin/bash
#usage install-zlib.sh <directory> <version> <url> <parallelism> <openssl dir>

set -exo pipefail

DEPENDENCIES_DIR=$1
VERSION=$2
DEPENDENCIES_URL=$3
MAKE_JOBS=$4
OPENSSL_DIRECTORY=$5

cd $DEPENDENCIES_DIR
wget $DEPENDENCIES_URL/poco-$VERSION-all.tar.gz
tar -xzf poco-$VERSION-all.tar.gz
cd poco-$VERSION-all
./configure --prefix=./target --static --no-samples --no-tests --omit=Data,Data/MySQL,Data/ODBC,Data/SQLite,Zip,MongoDB,PageCompiler,PageCompiler/File2Page,Redis --include-path=$OPENSSL_DIRECTORY/target/include --cflags="-DPOCO_UTIL_NO_XMLCONFIGURATION -DPOCO_UTIL_NO_JSONCONFIGURATION"
make -j $MAKE_JOBS install

