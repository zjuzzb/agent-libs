#!/bin/bash
set -exo pipefail

#setup all the env vars
CODE_DIR=/draios #location where input code is
WORK_DIR=/code   #location where code is copied to prevent edits conflicting with ongonig build
BUILD_DIR=$WORK_DIR/agent/build
PACKAGE_DIR=/out #certain targets provide a specific set of packages. they go here, for better or worse

MAKE_JOBS=${MAKE_JOBS:-1}

DEPENDENCIES_DIR=$WORK_DIR/agent/dependencies
JAVA_DIR=$DEPENDENCIES_DIR/$(
    cd $DEPENDENCIES_DIR
    ls | grep jdk | head -n 1
)

if [ -z "$AGENT_VERSION" ]; then
    AGENT_VERSION="0.1.1dev"
fi
if [ -z "$AGENT_BUILD_DATE" ]; then
    AGENT_BUILD_DATE="$(date -u -Iseconds)"
fi
if [ -z "$AGENT_BUILD_COMMIT" -a -d $CODE_DIR/agent/.git ]; then
    pushd $CODE_DIR/agent/
    AGENT_BUILD_COMMIT="$(git rev-parse --short HEAD)"
    popd
fi

rsync --delete -t -r --exclude=.git --exclude=dependencies --exclude=dependency_install_scripts --exclude=build $CODE_DIR/agent/ $WORK_DIR/agent/
rsync --delete -t -r --exclude=.git --exclude=dependencies --exclude=build --exclude='userspace/engine/lua/lyaml*' $CODE_DIR/oss-falco/ $WORK_DIR/oss-falco/
rsync --delete -t -r --exclude=.git --exclude=dependencies --exclude=build $CODE_DIR/protorepo/ $WORK_DIR/protorepo/
rsync --delete -t -r --exclude=.git --exclude=dependencies --exclude=build $CODE_DIR/probe-builder/ $WORK_DIR/probe-builder/
rsync --delete -t -r --exclude=.git --exclude=dependencies --exclude=build $CODE_DIR/agent-libs/ $WORK_DIR/agent-libs/

configure_build()
{
    # Determine architecture-specific CMAKE options
    ARCH=$(uname -m)
    if [[ "$ARCH" == "s390x" ]]; then
    	CMAKE_ARCH_SPECIFIC_OPTIONS=(
    		"-DDRAIOS_ARCH_YAML_VERSION="5.2"
    		"-DDRAIOS_ARCH_LUA_VERSION="5.2.4"
    	)
    elif [[ "$ARCH" == "aarch64" ]]; then
    	CMAKE_ARCH_SPECIFIC_OPTIONS=(
    		"-DDRAIOS_ARCH_YAML_VERSION="5.2"
    		"-DDRAIOS_ARCH_LUA_VERSION="5.2.4"
    	)
    else
    	CMAKE_ARCH_SPECIFIC_OPTIONS=(
    		"-DDRAIOS_ARCH_YAML_VERSION=5.1"
    		"-DDRAIOS_ARCH_LUA_VERSION=2.0.3"
    		"-DDRAIOS_ARCH_SUPPORTS_LUAJIT=TRUE"
    		"-DDRAIOS_ARCH_SUPPORTS_PYTHON_35=TRUE"
    		"-DDRAIOS_ARCH_BUILD_32_BIT_TESTS=TRUE"
    	)
    fi

    mkdir -p $BUILD_DIR/$VARIANT
    pushd $BUILD_DIR/$VARIANT
    scl enable devtoolset-2 "$DEPENDENCIES_DIR/cmake-3.5.2/bin/cmake \
		-DCMAKE_BUILD_TYPE=$VARIANT \
		-DDRAIOS_DEPENDENCIES_DIR=$DEPENDENCIES_DIR \
		-DJAVA_HOME=$JAVA_DIR \
		-DAGENT_VERSION="$AGENT_VERSION" \
		-DAGENT_BUILD_COMMIT="${AGENT_BUILD_COMMIT:-}" \
		-DAGENT_BUILD_DATE="$AGENT_BUILD_DATE" \
		-DSTATSITE_VERSION=${STATSITE_VERSION:-0.7.0-sysdig7} \
		-DBUILD_DRIVER=${BUILD_DRIVER:-OFF} \
		-DBUILD_BPF=${BUILD_BPF:-OFF} \
		-DPACKAGE_DEB_ONLY=${BUILD_DEB_ONLY:-OFF} \
		-DCMAKE_INSTALL_PREFIX="${CMAKE_INSTALL_PREFIX:-/opt/draios}" \
		-DCOMBINED_PACKAGE=${COMBINED_PACKAGE:-ON} \
		-DBUILD_WARNINGS_AS_ERRORS=${BUILD_WARNINGS_AS_ERRORS:-ON} \
		-DRELOCATED_CHISELS="ON" \
		-DLIBSINSP_DIR=$WORK_DIR/agent-libs \
		-DLIBSCAP_DIR=$WORK_DIR/agent-libs \
		${CMAKE_ARCH_SPECIFIC_OPTIONS[@]} \
		$WORK_DIR/agent"
    popd
}

build_container()
{
    case "$CONTAINER_TYPE" in
        agent)
            build_agent_container
            ;;
        agentone)
            build_agentone_container
            ;;
        *)
            echo "Invalid Container type: \"$CONTAINER_TYPE\""
            ;;
    esac
}

build_agent_container()
{
    VARIANT="ReleaseInternal"
    BUILD_DEB_ONLY=ON
    configure_build
    DOCKER_CONTEXT=$(mktemp -d /out/agent-container.XXXXXX)

    pushd $BUILD_DIR/$VARIANT
    make -j$MAKE_JOBS package

    cp draios-*-agent.deb "$DOCKER_CONTEXT"
    cp docker/local/docker-entrypoint.sh "$DOCKER_CONTEXT"
    awk -v "new_ver=$AGENT_VERSION" '/^ENV AGENT_VERSION/ { $3 = new_ver } { print }' <docker/local/Dockerfile >"$DOCKER_CONTEXT/Dockerfile"
    popd

    pushd $DOCKER_CONTEXT
    docker build -t ${AGENT_IMAGE:-agent:latest-local} .
    popd

    rm -rf $DOCKER_CONTEXT
}

build_agentone_container()
{
    VARIANT="ReleaseInternal"
    BUILD_DEB_ONLY=ON
    configure_build
    DOCKER_CONTEXT=$(mktemp -d /out/agent-container.XXXXXX)

    pushd $BUILD_DIR/$VARIANT
    make -j$MAKE_JOBS package

    cp draios-0.1.1dev-x86_64-agentone.deb "$DOCKER_CONTEXT"
    cp docker/agentone/local/Dockerfile "$DOCKER_CONTEXT"
    cp docker/agentone/local/agentone-entrypoint.sh "$DOCKER_CONTEXT"
    popd

    pushd "$DOCKER_CONTEXT"
    docker build -t ${AGENT_IMAGE:-agentone:latest-local} .
    popd

    rm -rf "$DOCKER_CONTEXT"
}

build_make()
{
    configure_build
    pushd $BUILD_DIR/$VARIANT
    make -j$MAKE_JOBS $TARGET
    popd
}

build_sonar()
{
    VARIANT="DebugInternalCodeCoverage"
    BW_OUTPUT="$BUILD_DIR/$VARIANT/bw-output"
    # everything must be guaranteed to be rebuilt
    pushd $BUILD_DIR/$VARIANT
    rm -rf *
    popd

    configure_build

    pushd $BUILD_DIR/$VARIANT
    $DEPENDENCIES_DIR/sonarcloud/build-wrapper-linux-x86/build-wrapper-linux-x86-64 \
        --out-dir $BW_OUTPUT \
        make -j$MAKE_JOBS all
    popd

    # Change into the directory to set the "project basedir". All files
    # scanned must be in this directory.
    pushd $WORK_DIR/agent

    $DEPENDENCIES_DIR/sonarcloud/sonar-scanner-4.3.0.2102-linux/bin/sonar-scanner \
        -Dsonar.organization=draios \
        -Dsonar.projectKey=draios_agent \
        -Dsonar.sources=$WORK_DIR/agent \
        -Dsonar.host.url=https://sonarcloud.io \
        -Dsonar.cfamily.build-wrapper-output=$BW_OUTPUT \
        -Dsonar.login=d8ce213c92157d883015102baabb7193f5153b78 \
        -Dsonar.inclusions=userspace/**/*.cpp \
        -Dsonar.test.exclusions=userspace/**/test/*.cpp

    popd
}

build_package()
{
    VARIANT=Release
    configure_build
    pushd $BUILD_DIR/$VARIANT
    make -j$MAKE_JOBS package
    popd

    # We run cmake twice, changing the value
    # of COMBINED_PACKAGE, so in one invocation we get the agent package
    # with the agent-slim/agent-kmodule components combined into a single
    # agent package, and in the other invocation we get separate packages
    # for each component
    COMBINED_PACKAGE=OFF
    configure_build
    pushd $BUILD_DIR/$VARIANT
    make -j$MAKE_JOBS package
    popd

    cp $BUILD_DIR/$VARIANT/*.deb $BUILD_DIR/$VARIANT/*.rpm $PACKAGE_DIR
}

build_release()
{
    VARIANT=Release
    configure_build
    pushd $BUILD_DIR/$VARIANT
    make -j$MAKE_JOBS install package
    popd

    VARIANT=Debug
    configure_build
    pushd $BUILD_DIR/$VARIANT
    make -j$MAKE_JOBS install package
    popd

    COMBINED_PACKAGE=OFF
    VARIANT=Release
    configure_build
    pushd $BUILD_DIR/$VARIANT
    make -j$MAKE_JOBS install package
    mkdir -p $PACKAGE_DIR/Release
    cp *.deb *.rpm *.tar.gz $PACKAGE_DIR/Release
    popd

    VARIANT=Debug
    configure_build
    pushd $BUILD_DIR/$VARIANT
    make -j$MAKE_JOBS install package
    mkdir -p $PACKAGE_DIR/Debug
    cp *.deb *.rpm *.tar.gz $PACKAGE_DIR/Debug
    popd
}

build_benchmarks()
{
    VARIANT=ReleaseInternal
    configure_build
    pushd $BUILD_DIR/$VARIANT
    make -j$MAKE_JOBS benchmarks

    # Copy all files that start with "benchmark-" to /out
    for SRC in $(find "$BUILD_DIR/${VARIANT}" -name 'benchmark-*' -type f -print); do
        echo "copy $SRC to ${PACKAGE_DIR}"
        cp $SRC $PACKAGE_DIR
    done
    popd
}

case "$1" in
    bash)
        bash
        ;;
    container)
        CONTAINER_TYPE=${2:-agent}
        build_container
        ;;
    make)
        TARGET=${2:-all}
        VARIANT=${3:-ReleaseInternal}
        build_make
        ;;
    sonar)
        build_sonar
        ;;
    package)
        build_package
        ;;
    release)
        build_release
        ;;
    presubmit)
        TARGET="all valgrind-unit-tests"
        VARIANT=DebugInternal
        build_make
        ;;
    benchmarks)
        build_benchmarks
        ;;
        # legacy targets we should kill
    agentone) #should be "container agentone"
        CONTAINER_TYPE=agentone
        build_container
        ;;
    install-test) ;&

    install)
        TARGET="install"
        build_make
        ;;

    # Catch "help", no arguments, or invalid arguments
    *)
        set +x
        cat <<EOF
	Usage:
	bash
	container [agent|agentone]
	make [target] [variant]
	sonar
	package
	release
	presubmit
	benchmarks
EOF
        set -x
        ;;
esac
