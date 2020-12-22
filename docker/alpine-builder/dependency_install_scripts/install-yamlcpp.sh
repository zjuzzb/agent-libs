#!/bin/bash
#usage install-yamlcpp.sh <directory> <version> <url> <parallelism> <boost dir> <cmake dir>

set -exo pipefail

DEPENDENCIES_DIR=$1
VERSION=$2
DEPENDENCIES_URL=$3
MAKE_JOBS=$4
BOOST_DIRECTORY=$5
CMAKE_DIRECTORY=$6

cd $DEPENDENCIES_DIR
wget $DEPENDENCIES_URL/yaml-cpp-$VERSION.tar.gz
tar xfz yaml-cpp-$VERSION.tar.gz
cd yaml-cpp-$VERSION
mkdir build
cd build
BOOST_ROOT=$BOOST_DIRECTORY $CMAKE_DIRECTORY/bin/cmake -DCMAKE_INSTALL_PREFIX=$DEPENDENCIES_DIR/yaml-cpp-$VERSION/target -DYAML_CPP_BUILD_CONTRIB=OFF ..
make -j $MAKE_JOBS install
