#!/bin/bash
set -exo pipefail

SCRIPT_DIR="$(dirname "${BASH_SOURCE[0]}")"
AGENT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd -P)"

DOCKER_CONTEXT=$(mktemp -d /tmp/build-context.XXXXXX)
cp $SCRIPT_DIR/* $DOCKER_CONTEXT

mkdir $DOCKER_CONTEXT/dependency_install_scripts
cp $SCRIPT_DIR/../dependency_install_scripts/*  $DOCKER_CONTEXT/dependency_install_scripts/
mv $DOCKER_CONTEXT/install-deps.sh $DOCKER_CONTEXT/dependency_install_scripts/

# Add go.mod and go.sum files used to prefetch go modules.
mkdir $DOCKER_CONTEXT/go_mods
pushd $AGENT_ROOT/userspace/cointerface/src
cp --parents $(find . -name go.mod -o -name go.sum) $DOCKER_CONTEXT/go_mods/
popd

pushd $DOCKER_CONTEXT
docker build --build-arg max_parallelism=${MAKE_JOBS:-1} -t ${IMAGE_NAME:-centos-builder:latest-local} -f Dockerfile .
popd

rm -rf $DOCKER_CONTEXT
