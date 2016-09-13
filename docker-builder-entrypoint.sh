#!/bin/bash
set -exo pipefail

if [[ -z $MAKE_JOBS ]]; then
  MAKE_JOBS=1
fi
export BUILD_DRIVER=OFF

if [[ -z $AGENT_IMAGE ]]; then
  AGENT_IMAGE="agent:latest"
fi

rsync --delete -t -r --exclude=.git --exclude=dependencies --exclude=build /draios/agent/ /code/agent/
rsync --delete -t -r --exclude=.git --exclude=dependencies --exclude=build /draios/sysdig/ /code/sysdig/
rsync --delete -t -r --exclude=.git --exclude=dependencies --exclude=build --exclude=userspace/engine/lua /draios/falco/ /code/falco/
cd /code/agent
scl enable devtoolset-2 ./bootstrap-agent
cd build/release
if [[ $1 == "package" ]]; then
  make -j$MAKE_JOBS package
  cp /code/agent/docker/local/* /out
  cp *.deb *.rpm /out
  cd /out
  docker build -t $AGENT_IMAGE .
elif [[ $1 == "install" ]]; then
  make -j$MAKE_JOBS install
fi
