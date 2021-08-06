#!/bin/bash
#usage install-jdk.sh <directory> <version> <url> <parallelism>

set -exo pipefail

DEPENDENCIES_DIR=$1
VERSION=$2
DEPENDENCIES_URL=$3
MAKE_JOBS=$4

cd $DEPENDENCIES_DIR
wget $DEPENDENCIES_URL/jdk-$VERSION-linux-x64.tar.bz2
tar -xjf jdk-$VERSION-linux-x64.tar.bz2
