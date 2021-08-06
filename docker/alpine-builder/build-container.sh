#!/bin/bash
set -exo pipefail

SCRIPT_DIR=$(dirname $(readlink -f $0))

DOCKER_CONTEXT=$(mktemp -d /tmp/build-context.XXXXXX)
cp $SCRIPT_DIR/* $DOCKER_CONTEXT

mkdir $DOCKER_CONTEXT/dependency_install_scripts
cp $SCRIPT_DIR/../dependency_install_scripts/*  $DOCKER_CONTEXT/dependency_install_scripts/
mv $DOCKER_CONTEXT/install-deps.sh $DOCKER_CONTEXT/dependency_install_scripts/

pushd $DOCKER_CONTEXT
docker build --build-arg max_parallelism=${MAKE_JOBS:-1} -t ${IMAGE_NAME:-alpine-builder:latest-local} -f Dockerfile .
popd

rm -rf $DOCKER_CONTEXT
