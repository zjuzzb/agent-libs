#!/bin/bash
#usage install-scons.sh <directory> <version> <url> <parallelism>

set -exo pipefail

DEPENDENCIES_DIR=$1
VERSION=$2
DEPENDENCIES_URL=$3
MAKE_JOBS=$4

cd $DEPENDENCIES_DIR
wget $DEPENDENCIES_URL/scons-$VERSION.tar.gz
tar xfz scons-$VERSION.tar.gz
