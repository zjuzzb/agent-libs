#!/bin/bash
#usage install-maven.sh <directory> <version> <url> <parallelism>

set -exo pipefail

DEPENDENCIES_DIR=$1
VERSION=$2
DEPENDENCIES_URL=$3
MAKE_JOBS=$4

cd $DEPENDENCIES_DIR
wget $DEPENDENCIES_URL/apache-maven-$VERSION-bin.tar.gz
tar -xzf apache-maven-$VERSION-bin.tar.gz
