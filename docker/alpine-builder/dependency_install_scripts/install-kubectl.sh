#!/bin/bash
#usage install-kubectl.sh <directory> <version> <url> <parallelism>

set -exo pipefail

DEPENDENCIES_DIR=$1
VERSION=$2
DEPENDENCIES_URL=$3
MAKE_JOBS=$4

cd $DEPENDENCIES_DIR
wget https://storage.googleapis.com/kubernetes-release/release/v$VERSION/bin/linux/amd64/kubectl -O $DEPENDENCIES_DIR/kubectl-$VERSION
