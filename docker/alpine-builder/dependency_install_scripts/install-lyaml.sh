#!/bin/bash
#usage install-lyaml.sh <directory> <version> <url> <parallelism> <luajit dir> <libyaml dir>

set -exo pipefail

DEPENDENCIES_DIR=$1
VERSION=$2
DEPENDENCIES_URL=$3
MAKE_JOBS=$4
LUAJIT_DIRECTORY=$5
LIBYAML_DIRECTORY=$6

cd $DEPENDENCIES_DIR
wget $DEPENDENCIES_URL/lyaml-release-v$VERSION.tar.gz
tar -xzf lyaml-release-v$VERSION.tar.gz
cd lyaml-release-v$VERSION
CONFLUA=${LUAJIT_DIRECTORY}/src/lua
if [ -e "${CONFLUA}jit" ]; then
    CONFLUA="${CONFLUA}jit"
fi
LD_LIBRARY_PATH="${LIBYAML_DIRECTORY}/target/lib" ./configure --prefix=$DEPENDENCIES_DIR/lyaml-release-v$VERSION/target --enable-static LIBS=-L${LIBYAML_DIRECTORY}/target/lib CFLAGS=-I${LIBYAML_DIRECTORY}/target/include CPPFLAGS=-I${LIBYAML_DIRECTORY}/target/include LUA_INCLUDE=-I${LUAJIT_DIRECTORY}/src LUA=${CONFLUA}
make -j $MAKE_JOBS
make -j $MAKE_JOBS install
mkdir -p /code/oss-falco/userspace/engine/lua
sh -c "cp -R ${DEPENDENCIES_DIR}/lyaml-release-v${VERSION}/lib/* /code/oss-falco/userspace/engine/lua"
