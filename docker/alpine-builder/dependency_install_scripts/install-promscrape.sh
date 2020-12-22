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

#note: you can download and link whatever version you want at run-time if you don't want
#      dev at the time the container was built
wget -O promscrape_v1-$VERSION $DEPENDENCIES_URL/promscrape/v1/promscrape_v1-$VERSION
ln -s promscrape_v1-$VERSION promscrape_v1

wget -O promscrape_v2-$VERSION $DEPENDENCIES_URL/promscrape/v2/promscrape_v2-$VERSION
ln -s promscrape_v2-$VERSION promscrape_v2

