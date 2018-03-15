#!/bin/bash
set -exo pipefail

if [[ -z $MAKE_JOBS ]]; then
  MAKE_JOBS=1
fi
export BUILD_DRIVER=OFF

if [[ -z $AGENT_IMAGE ]]; then
  AGENT_IMAGE="agent:latest"
fi

rsync --delete -t -r --exclude=.git --exclude=dependencies --exclude=build --exclude="cointerface/draiosproto" --exclude="cointerface/sdc_internal" /draios/agent/ /code/agent/
rsync --delete -t -r --exclude=.git --exclude=dependencies --exclude=build --exclude='driver/Makefile' --exclude='driver/driver_config.h' /draios/sysdig/ /code/sysdig/
rsync --delete -t -r --exclude=.git --exclude=dependencies --exclude=build --filter='P userspace/engine/lua/lyaml*' /draios/falco/ /code/falco/
cd /code/agent

DOCKERFILE=Dockerfile
if [[ "`uname -m`" == "s390x" ]]; then
./bootstrap-agent
DOCKERFILE=Dockerfile.s390x
else

if [[ $1 == "container" ]]; then
  export BUILD_DEB_ONLY=ON
fi

scl enable devtoolset-2 ./bootstrap-agent
fi
cd build/release
if [[ $1 == "package" || $1 == "container" ]]; then
  make -j$MAKE_JOBS package
  cp /code/agent/docker/local/* /out
  cp *.deb /out
  if [[ $1 == "package" ]]; then
	  cp *.rpm /out
  fi
  cd /out
  docker build -t $AGENT_IMAGE -f $DOCKERFILE .
elif [[ $1 == "install" ]]; then
  make -j$MAKE_JOBS install
elif [[ $1 == "bash" ]]; then
  bash
fi
