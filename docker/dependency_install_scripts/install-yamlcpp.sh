#!/bin/bash
#usage install-yamlcpp.sh <deps-directory> <version> <yaml-dir> <url> <parallelism> <cmake dir>

set -exo pipefail

DEPENDENCIES_DIR=$1
VERSION=$2
YAML_DIR=$3
DEPENDENCIES_URL=$4
MAKE_JOBS=$5
CMAKE_DIRECTORY=$6

cd $DEPENDENCIES_DIR
wget $DEPENDENCIES_URL/yaml-cpp-yaml-cpp-${VERSION}.tar.gz
wget $DEPENDENCIES_URL/yaml-cpp-${VERSION}-fix.patch
rm -rf yaml-cpp-yaml-cpp-${VERSION}
tar xfz yaml-cpp-yaml-cpp-${VERSION}.tar.gz
mv yaml-cpp-yaml-cpp-${VERSION} $YAML_DIR
cd $YAML_DIR
patch -p1 < $DEPENDENCIES_DIR/yaml-cpp-${VERSION}-fix.patch
mkdir build
cd build
$CMAKE_DIRECTORY/bin/cmake -DCMAKE_INSTALL_PREFIX=$YAML_DIR/target -DYAML_CPP_BUILD_CONTRIB=OFF ..
make -j $MAKE_JOBS install
