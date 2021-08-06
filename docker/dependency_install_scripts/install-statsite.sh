#!/bin/bash
#usage install-statsite.sh <directory> <version> <url> <parallelism> <python dir> <scons dir>

set -exo pipefail

DEPENDENCIES_DIR=$1
VERSION=$2
DEPENDENCIES_URL=$3
MAKE_JOBS=$4
PYTHON_DIR=$5
SCONS_DIR=$6

cd $DEPENDENCIES_DIR
wget $DEPENDENCIES_URL/statsite-private-$VERSION.zip
unzip statsite-private-$VERSION.zip
cd statsite-private-$VERSION
$PYTHON_DIR/target/bin/python $SCONS_DIR/script/scons
