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

rsync --delete -t -r --exclude=.git --exclude=dependencies --exclude=build --exclude="cointerface/src/*/draiosproto" --exclude="cointerface/src/*/sdc_internal" --exclude="cointerface/src/*/promex_pb" /draios/agent/ /code/agent/
rsync --delete -t -r --exclude=.git --exclude=dependencies --exclude=build --exclude='driver/Makefile' --exclude='driver/driver_config.h' /draios/sysdig/ /code/sysdig/
rsync --delete -t -r --exclude=.git --exclude=dependencies --exclude=build --exclude='userspace/engine/lua/lyaml*' /draios/oss-falco/ /code/oss-falco/

if [[ $1 == "container" ]]; then
	# Must be set before calling cmake in bootstrap-agent
	export BUILD_DEB_ONLY=ON
fi

if [[ "`uname -m`" == "s390x" ]]; then
	DOCKERFILE=Dockerfile.s390x
	bootstrap_agent() {
		local build_target="${1:-"release"}"

		cd /code/agent
		./bootstrap-agent
		# bootstrap-agent creates a folder for every build target, so
		# we just switch into the appropriate folder
		cd "/code/agent/build/${build_target}"
	}
else
	DOCKERFILE=Dockerfile
	bootstrap_agent() {
		local build_target="${1:-"release"}"

		cd /code/agent
		scl enable devtoolset-2 ./bootstrap-agent
		# bootstrap-agent creates a folder for every build target, so
		# we just switch into the appropriate folder
		cd "/code/agent/build/${build_target}"
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

build_benchmarks()
{
	local build_target="${1:-"release-internal"}"

	bootstrap_agent "${build_target}"
	make -j$MAKE_JOBS benchmarks

	# Copy all files that start with "benchmark-" to /out
	for SRC in $(find "/code/agent/build/${build_target}" -name 'benchmark-*' -type f -print); do
		echo "copy $SRC to /out"
		cp $SRC /out
	done
}

build_package()
{
	local build_target="release"

	bootstrap_agent "${build_target}"
	make -j$MAKE_JOBS package

	# We run bootstrap_agent twice to run cmake twice, changing the value
	# of COMBINED_PACKAGE, so in one invocation we get the agent package
	# with the agent-slim/agent-kmodule components combined into a single
	# agent package, and in the other invocation we get separate packages
	# for each component
	COMBINED_PACKAGE=OFF bootstrap_agent "${build_target}"
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

# $1 is release/debug
# $2 is filename
build_single_cpp()
{
	# We're searching through Makefiles for the filename followed by a .o
	# extension and a colon: "dragent.cpp.o:"
	# Note that sometimes this can be in a folder.

	# Find all Makefiles having a "$2.o" target
	# -F -- simple string match, not a regex
	# -r -- recurse down directories
	# -l -- output file names only
	# -w -- whole word matching
	grep -Frlw --include Makefile "$2.o:" /code/agent/build/$1 | while read makefilePath
	do
		# Get the full text of the target, including any directories
		target="$(grep -Fw $2.o: $makefilePath)"
		# Remove the colon
		target=${target%?}

		# chdir to the Makefile directory and make the target
		builddir=$(dirname $makefilePath)
		echo "building $target in $builddir"
		make -C $builddir $target
	done
}

# $1 is release/debug
# $2 is first argument
# $3 is second argument
build_target()
{
    if [ -z "$2" ]; then
	    # There is no second argument so just call make all
	    bootstrap_agent $1
	    make -j$MAKE_JOBS all
    else
	    if [ ${2: -4} == ".cpp" ]; then
		    # This is a cpp file, so just build that file
		    build_single_cpp $1 $2
	    else
		    # Make a specific target
		    bootstrap_agent $1
		    make -j$MAKE_JOBS $2 $3
	    fi
    fi

}

#
# Run whatever builds/tests we want to run within the build container before
# we submit.
build_presubmit()
{
	# Use the debug-internal build because it has the toughest valgrind
	(bootstrap_agent "debug-internal" && make -j${MAKE_JOBS} all run-unit-tests) || \
		(echo "Building presubmit failed" && false)
}
readonly -f build_presubmit

function bold() {
	local -r bold=$(tput bold)
	local -r normal=$(tput sgr0)

    echo "${bold}${@}${normal}"
}
readonly -f bold

case "$1" in
	bash)
		bootstrap_agent "${2:-"release-internal"}"
		bash
		;;
	container)
		bootstrap_agent "${2:-"release-internal"}"
		build_container
		;;
	install-test)
		;& # deprecated; just fall through
	install)
		bootstrap_agent "${2:-"release-internal"}"
		make -j$MAKE_JOBS install
		;;
	benchmarks)
		# used by the agent-build-benchmarks jenkins job
		build_benchmarks
		;;
	package)
		build_package
		;;
	release)
		# used by the agent-build-docker-dev and agent-build-docker-rc
		# jenkins jobs
		build_release
		;;
	sysdig)
		build_sysdig
		;;
	presubmit)
		# used by the agent-build-presubmit jenkins job
		build_presubmit
		;;
	make-release)
		build_target "release" $2 $3
		;;
	make-debug)
		build_target "debug" $2 $3
		;;
	make)
		;& # fall through to make-release-internal
	make-release-internal)
		build_target "release-internal" $2 $3
		;;
	make-debug-internal)
		build_target "debug-internal" $2 $3
		;;
	make-debug-internal-code-coverage)
		build_target "debug-internal-code-coverage" $2 $3
		;;

	# Catch "help", no arguments, or invalid arguments
	*)
        set +x
		cat << EOF
	This is the entry point for the Sysdig agent-builder.

	5 Build variants are supported:
	1. debug
	2. release
	3. debug-internal
	4. release-internal
	5. debug-internal-code-coverage
	Most commands have a default variant and most support passing a
	specific variant.

	To build and generate the agent container:
	$(bold "> agent-builder container")
	$(bold "> agent-builder container <variant>")

	To build the release-internal agent and install to the local machine:
	$(bold "> agent-builder install")
	$(bold "> agent-builder install <variant>")

	To build a particular target or file:
	$(bold "> agent-builder make")
	$(bold "> agent-builder make dragent")
	$(bold "> agent-builder make analyzer.cpp")

	To see a list of possible targets:
	$(bold "> agent-builder make help")

	To get a bash shell inside the builder:
	$(bold "> agent-builder bash")

	To build a particular target or file for a specific variant:
	$(bold "> agent-builder make-debug-internal unit-test-dragent")
EOF
        set -x
		;;
esac
