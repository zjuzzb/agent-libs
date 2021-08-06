#!/bin/bash
#usage install-sonarcloud.sh <directory> <version> <url> <parallelism>

set -exo pipefail

DEPENDENCIES_DIR=$1
VERSION=$2
DEPENDENCIES_URL=$3
MAKE_JOBS=$4

cd $DEPENDENCIES_DIR
mkdir sonarcloud
cd sonarcloud
wget $DEPENDENCIES_URL/build-wrapper-linux-x86.zip
unzip build-wrapper-linux-x86.zip
wget $DEPENDENCIES_URL/sonar-scanner-cli-4.3.0.2102-linux.zip
unzip sonar-scanner-cli-4.3.0.2102-linux.zip
