#!/bin/bash
#usage install-json.sh <directory> <version> <url> <parallelism>

set -exo pipefail

DEPENDENCIES_DIR=$1
VERSION=$2
DEPENDENCIES_URL=$3
MAKE_JOBS=$4

cd $DEPENDENCIES_DIR
wget $DEPENDENCIES_URL/njson-$VERSION.tar.gz
tar -xzf njson-$VERSION.tar.gz
