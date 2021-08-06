#!/bin/bash
#usage install-boost.sh <directory> <version> <url> <parallelism>

set -exo pipefail

DEPENDENCIES_DIR=$1
VERSION=$2
DEPENDENCIES_URL=$3
MAKE_JOBS=$4

cd $DEPENDENCIES_DIR
wget $DEPENDENCIES_URL/boost_$VERSION.tar.bz2
tar xfj boost_$VERSION.tar.bz2
