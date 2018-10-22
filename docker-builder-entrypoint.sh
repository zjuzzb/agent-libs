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
rsync --delete -t -r --exclude=.git --exclude=dependencies --exclude=build --exclude='userspace/engine/lua/lyaml*' /draios/oss-falco/ /code/oss-falco/

if [[ $1 == "container" ]]; then
	# Must be set before calling cmake in boostrap-agent
	export BUILD_DEB_ONLY=ON
fi

if [[ "`uname -m`" == "s390x" ]]; then
	DOCKERFILE=Dockerfile.s390x
	bootstrap_agent() {
		cd /code/agent
		./bootstrap-agent
		cd /code/agent/build/release
	}
else
	DOCKERFILE=Dockerfile
	bootstrap_agent() {
		cd /code/agent
		scl enable devtoolset-2 ./bootstrap-agent
		cd /code/agent/build/release
	}
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
	bootstrap_agent
	make -j$MAKE_JOBS package

	# We run bootstrap_agent twice to run cmake twice, changing the value
	# of COMBINED_PACKAGE, so in one invocation we get the agent package
	# with the agent-slim/agent-kmodule components combined into a single
	# agent package, and in the other invocation we get separate packages
	# for each component
	COMBINED_PACKAGE=OFF bootstrap_agent
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

	bootstrap_agent
	make -j$MAKE_JOBS install package

	cd ../debug
	make -j$MAKE_JOBS package

	# see comment in build_package above
	COMBINED_PACKAGE=OFF bootstrap_agent
	make -j$MAKE_JOBS package

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

case "$1" in
	bash)
		bootstrap_agent
		bash
		;;
	container)
		bootstrap_agent
		build_container
		;;
	install)
		bootstrap_agent
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
