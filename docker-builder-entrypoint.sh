#!/bin/bash
set -exo pipefail

if [[ -z $MAKE_JOBS ]]; then
  MAKE_JOBS=1
fi
export BUILD_DRIVER=OFF

if [[ -z $AGENT_IMAGE ]]; then
  AGENT_IMAGE="agent:latest"
fi

if [[ -z $SYSDIG_IMAGE ]]; then
  SYSDIG_IMAGE="sysdig:latest"
fi

rsync --delete -t -r --exclude=.git --exclude=dependencies --exclude=build --exclude="cointerface/draiosproto" --exclude="cointerface/sdc_internal" /draios/agent/ /code/agent/
rsync --delete -t -r --exclude=.git --exclude=dependencies --exclude=build --exclude='driver/Makefile' --exclude='driver/driver_config.h' /draios/sysdig/ /code/sysdig/
rsync --delete -t -r --exclude=.git --exclude=dependencies --exclude=build --exclude='userspace/engine/lua/lyaml*' /draios/falco/ /code/falco/
cd /code/agent

if [[ $1 == "container" ]]; then
	# Must be set before calling cmake in boostrap-agent
	export BUILD_DEB_ONLY=ON
fi

DOCKERFILE=Dockerfile
if [[ "`uname -m`" == "s390x" ]]; then
  ./bootstrap-agent
  DOCKERFILE=Dockerfile.s390x
else
  scl enable devtoolset-2 ./bootstrap-agent
fi

build_docker_image()
{
	cp docker/local/docker-entrypoint.sh /out
	if [ -n "$AGENT_VERSION" ]
	then
		awk -v "new_ver=$AGENT_VERSION" '/^ENV AGENT_VERSION/ { $3 = new_ver } { print }' < docker/local/$DOCKERFILE > /out/$DOCKERFILE
	else
	        cp docker/local/$DOCKERFILE /out/$DOCKERFILE
	fi
	cd /out
	docker build -t $AGENT_IMAGE -f $DOCKERFILE --pull .
}

build_package()
{
	make -j$MAKE_JOBS package
	cp *.deb *.rpm /out
}

build_container()
{
	make -j$MAKE_JOBS package
	cp *.deb /out
	build_docker_image
}

build_release()
{
	mkdir -p /out/{debug,release}

	make -j$MAKE_JOBS install package
	cp *.deb *.rpm *.tar.gz /out/release

	cd ../debug
	make -j$MAKE_JOBS package
	cp *.deb *.rpm *.tar.gz /out/debug
}

build_sysdig()
{
	cd /code/agent
	scl enable devtoolset-2 ./bootstrap-sysdig
	cd /code/sysdig/build/release
	make -j$MAKE_JOBS package
	cp /code/sysdig/docker/local/* /out
	cp *.deb /out
	cp *.rpm /out
	cd /out
	docker build -t $SYSDIG_IMAGE -f $DOCKERFILE --pull .
}

cd build/release

case "$1" in
	bash)
		bash
		;;
	container)
		build_container
		;;
	install)
		make -j$MAKE_JOBS install
		;;
	package)
		build_package
		;;
	release)
		build_release
		;;
	sysdig)
		build_sysdig
		;;
esac
