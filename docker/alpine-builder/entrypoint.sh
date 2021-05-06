#!/bin/bash
set -exo pipefail

#setup all the env vars
CODE_DIR=/draios #location where input code is
WORK_DIR=/code #location where code is copied to prevent edits conflicting with ongonig build
BUILD_DIR=$WORK_DIR/agent/build
HAYABUSA_PRODUCER_DIR=$WORK_DIR/libscap-hayabusa/producer_build
VARIANT=${2:-ReleaseInternal}

if [[ -z $MAKE_JOBS ]]; then
  export MAKE_JOBS=1
fi

DEPENDENCIES_DIR=$WORK_DIR/agent/dependencies
JAVA_DIR=$DEPENDENCIES_DIR/$(cd $DEPENDENCIES_DIR;ls | grep jdk | head -n 1)

if [ -z "$AGENT_VERSION" ]; then
    AGENT_VERSION="0.1.1dev"
fi
if [ -z "$AGENT_BUILD_DATE" ]; then
    AGENT_BUILD_DATE="`date`"
fi
if [ -z $STATSITE_VERSION ]; then
  STATSITE_VERSION=0.7.0-sysdig7
fi

if [[ -z $USE_OLD_DIRS ]]; then
    USE_OLD_DIRS="true"
fi

rsync --delete -t -r --exclude=.git --exclude=dependencies --exclude=dependency_install_scripts --exclude=build $CODE_DIR/agent/ $WORK_DIR/agent/
rsync --delete -t -r --exclude=.git --exclude=dependencies --exclude=build --exclude='userspace/engine/lua/lyaml*' $CODE_DIR/oss-falco/ $WORK_DIR/oss-falco/
rsync --delete -t -r --exclude=.git --exclude=dependencies --exclude=build $CODE_DIR/protorepo/ $WORK_DIR/protorepo/
rsync --delete -t -r --exclude=.git --exclude=producer_build $CODE_DIR/libscap-hayabusa/ $WORK_DIR/libscap-hayabusa
if [ "$USE_OLD_DIRS" = true ]
then
    rsync --delete -t -r --exclude=.git /draios/libsinsp/ /code/libsinsp/
    LIBSINSP_DIR=$WORK_DIR/libsinsp
    RELOCATED_CHISELS=OFF

else
    rsync --delete -t -r --exclude=.git /draios/agent-libs/ /code/agent-libs/
    LIBSINSP_DIR=$WORK_DIR/agent-libs
    RELOCATED_CHISELS=ON

fi
#note: don't support regular libscap or sysdig repo here, so they aren't synced

create_makefiles()
{
	pushd $BUILD_DIR
	cmake \
		-DCMAKE_BUILD_TYPE=$VARIANT \
		-DDRAIOS_DEPENDENCIES_DIR=$DEPENDENCIES_DIR \
		-DJAVA_HOME=$JAVA_DIR \
		-DAGENT_VERSION="$AGENT_VERSION" \
		-DAGENT_BUILD_COMMIT="${AGENT_BUILD_COMMIT:-}" \
		-DAGENT_BUILD_DATE="$AGENT_BUILD_DATE" \
		-DSTATSITE_VERSION=$STATSITE_VERSION \
		-DBUILD_DRIVER=${BUILD_DRIVER:-OFF} \
		-DBUILD_BPF=${BUILD_BPF:-OFF} \
		-DPACKAGE_DEB_ONLY=${BUILD_DEB_ONLY:-OFF} \
		-DCMAKE_INSTALL_PREFIX="${CMAKE_INSTALL_PREFIX:-/opt/draios}" \
		-DCOMBINED_PACKAGE=${COMBINED_PACKAGE:-OFF} \
		-DBUILD_WARNINGS_AS_ERRORS=${BUILD_WARNINGS_AS_ERRORS:-ON} \
		-DSTATIC_LINK=${STATIC_LINK:-ON} \
		-DALPINE_BUILDER=ON \
		-DRELOCATED_CHISELS=$RELOCATED_CHISELS \
		-DLIBSINSP_DIR=$LIBSINSP_DIR \
		-DLIBSCAP_DIR=$WORK_DIR/libscap-hayabusa \
		$WORK_DIR/agent
	popd
}

build_hayabusa_producers()
{	
	pushd $HAYABUSA_PRODUCER_DIR
	mkdir -p release
	pushd release
	cmake ../../
	make -j$MAKE_JOBS pdig-bin udigembed
	popd
	mkdir -p debug
	pushd debug
	cmake -DCMAKE_BUILD_TYPE=Debug ../../
	make -j$MAKE_JOBS pdig-bin udigembed
	popd
	popd
}

build_agentino()
{
	create_makefiles
	cd $BUILD_DIR
	make -j$MAKE_JOBS agentino
	build_hayabusa_producers


	DOCKER_CONTEXT=$(mktemp -d /out/agent-container.XXXXXX)
	cp userspace/dragent/src/agentino $DOCKER_CONTEXT
	cp $WORK_DIR/agent/userspace/dragent/src/dragent.default.yaml $DOCKER_CONTEXT
	cp $WORK_DIR/agent/userspace/dragent/src/root.cert $DOCKER_CONTEXT
	cp -r $WORK_DIR/oss-falco/userspace/engine/lua/* $DOCKER_CONTEXT
	cp $HAYABUSA_PRODUCER_DIR/release/libscap/producer/pdig/pdig $DOCKER_CONTEXT
	cp $HAYABUSA_PRODUCER_DIR/release/libscap/producer/udigembed/libudigembed.so $DOCKER_CONTEXT
	cp $HAYABUSA_PRODUCER_DIR/debug/libscap/producer/pdig/pdig $DOCKER_CONTEXT/pdig-debug
	cp $HAYABUSA_PRODUCER_DIR/debug/libscap/producer/udigembed/libudigembed.so $DOCKER_CONTEXT/libudigembed-debug.so

	make -j$MAKE_JOBS agentino-dockerfiles
	cp docker/agentino/static/* $DOCKER_CONTEXT

	pushd $DOCKER_CONTEXT
	strip agentino

	docker build -t ${AGENT_IMAGE:-agentino:latest} .

	popd
	rm -rf $DOCKER_CONTEXT
}

case "$1" in
	bash)
		bash
		;;
	agentino)
		build_agentino
		;;
	# Catch "help", no arguments, or invalid arguments
	*)
        set +x
		cat << EOF
		Supported Targets:
		- bash
		- agentino

		Second optional arg is variant:
		- Release
		- ReleaseInternal (default)
		- Debug
		- ...

		Required mounts:
		- /draios/agent
		- /draios/oss-falco
		- /draios/protorepo
		- /draios/libscap-hayabusa
		- /draios/libsinsp
EOF
        set -x
		;;
esac
