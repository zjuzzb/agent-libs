#!/bin/bash
#usage install-gtest.sh <directory> <version> <url> <parallelism>

set -exo pipefail

DEPENDENCIES_DIR=$1
VERSION=$2
DEPENDENCIES_URL=$3
MAKE_JOBS=$4

cd $DEPENDENCIES_DIR
wget $DEPENDENCIES_URL/gtest-$VERSION.zip
unzip gtest-$VERSION.zip
cd gtest-$VERSION
g++ -Iinclude -c fused-src/gtest/gtest-all.cc -o gtest-all.o
g++ -Iinclude -c fused-src/gtest/gtest_main.cc -o gtest_main.o
ar -rv libgtest.a gtest-all.o
ar -rv libgtest_main.a gtest_main.o

