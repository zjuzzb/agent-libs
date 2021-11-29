#!/bin/bash
#usage install-promscrape.sh <directory> <version> <url> <parallelism>

set -exo pipefail

DEPENDENCIES_DIR=$1
VERSION=$2
DEPENDENCIES_URL=$3
MAKE_JOBS=$4

cd $DEPENDENCIES_DIR
mkdir promscrape
cd promscrape

# Not allowing use of symbolic link here any more because CMAKE installs would just
# install the link and forget the binary
wget -O promscrape_v1 $DEPENDENCIES_URL/promscrape/v1/promscrape_v1-$VERSION
wget -O promscrape_v2 $DEPENDENCIES_URL/promscrape/v2/promscrape_v2-$VERSION
