#!/bin/bash
#usage install-kubebench.sh <directory> <version> <url> <parallelism>

set -exo pipefail

DEPENDENCIES_DIR=$1
VERSION=$2
DEPENDENCIES_URL=$3
MAKE_JOBS=$4

cd $DEPENDENCIES_DIR
wget $DEPENDENCIES_URL/kube-bench-$VERSION.tar.gz
tar -xzf kube-bench-$VERSION.tar.gz
