#!/bin/bash
#usage install-lpeg.sh <directory> <version> <url> <parallelism> <luajit dir>

set -exo pipefail

DEPENDENCIES_DIR=$1
VERSION=$2
DEPENDENCIES_URL=$3
MAKE_JOBS=$4
LUAJIT_DIRECTORY=$5

cd $DEPENDENCIES_DIR
wget $DEPENDENCIES_URL/lpeg-$VERSION.tar.gz
tar -xzf lpeg-$VERSION.tar.gz
cd lpeg-$VERSION
cp /code/oss-falco/scripts/build-lpeg-with-so.sh build-lpeg-with-so.sh
chmod 755 build-lpeg-with-so.sh
LUA_INCLUDE=${LUAJIT_DIRECTORY}/src "${DEPENDENCIES_DIR}/lpeg-${VERSION}/build-lpeg-with-so.sh" "${DEPENDENCIES_DIR}/lpeg-${VERSION}/target"
