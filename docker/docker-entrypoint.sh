#!/bin/bash
#set -e

SYSDIG_BUILD_KERNEL_MODULE=${SYSDIG_BUILD_KERNEL_MODULE:-1}

function mount_cgroup_subsys(){
	requested_subsys=$1
	subsys=$(awk -v subsys=$requested_subsys '
$(NF-2) == "cgroup" {
	sub(/(^|,)rw($|,)/, "", $NF)
	if (!printed && $NF ~ "(^|,)" subsys "($|,)") {
		print $NF
		printed=1
	}
}

END {
	if (!printed) {
		print subsys
	}
}' < /proc/self/mountinfo)
	echo "* Mounting $requested_subsys cgroup fs (using subsys $subsys)"
	mkdir -p $SYSDIG_HOST_ROOT/cgroup/$requested_subsys
	mount -t cgroup -o $subsys,ro none $SYSDIG_HOST_ROOT/cgroup/$requested_subsys
}

if [ "$SYSDIG_BUILD_KERNEL_MODULE" = "1" ]; then
    echo "* Setting up /usr/src links from host"

    for i in $(ls $SYSDIG_HOST_ROOT/usr/src)
    do
	ln -s $SYSDIG_HOST_ROOT/usr/src/$i /usr/src/$i
    done

    KERNEL_DIR=$SYSDIG_HOST_ROOT/lib/modules/$(uname -r)/build
    if [ ! -e "$KERNEL_DIR" ]
    then
	echo "* Kernel headers not found in $KERNEL_DIR, continuing anyway" >&2
    else
	# Try to find the gcc version used to build this particular kernel
	# Check CONFIG_GCC_VERSION=90201 in the kernel config first
	# as 5.8.0 seems to have a different format for the LINUX_COMPILER string
	if [ -e $KERNEL_DIR/include/generated/autoconf.h ]
	then
		GCC_VERSION=$(grep -Po '(?<=^#define CONFIG_GCC_VERSION ).*' $KERNEL_DIR/include/generated/autoconf.h | sed '-res@(.*)(..)(..)$@\1\.\2\.\3@' '-es@\.0@\.@g')
	else
		GCC_VERSION=
	fi
	if [ -z "$GCC_VERSION" ]
	then
	    for compile_h in $KERNEL_DIR/include/generated/compile.h $KERNEL_DIR/include/linux/compile.h
	    do
		if [ ! -e "$compile_h" ]
		then
		    continue
		fi

		GCC_VERSION=$(grep -Po '(?<=^#define LINUX_COMPILER "gcc version )[0-9.]+' $compile_h)
		break
	    done
	fi

	if [ -n "$GCC_VERSION" ]
	then
	    GCC_VERSION="${GCC_VERSION%.*}"
	    # gcc-4.8 and gcc-4.9 are symlinks to gcc (for legacy Debian kernels)
	    # so we skip them while trying to find a candidate to point gcc to
	    # (symlinking gcc to gcc-4.8 or gcc-4.9 would create a symlink loop)
	    GCC_BINARY=$(ls -U /usr/bin/gcc-[5-9]* | sed 's@^/usr/bin/gcc-@@' | sort -V | awk -v target=${GCC_VERSION} '
			$1 < target { older = $1 }
			$1 == target { exact = $1 }
			$1 > target && !newer { newer = $1 }

			END {
				if (exact) { print exact }
				else if (newer) { print newer }
				else { print older }
			}
			')

	    GCC_BINARY=/usr/bin/gcc-$GCC_BINARY
	    echo "* Will use $GCC_BINARY to build kernel module if needed"
	    ln -sf $GCC_BINARY /usr/bin/gcc
	fi
    fi
fi

KERNEL_ERR_MESSAGE="The Sysdig Agent kernel probe could not be built and a probe could not be found to download. Upgrading to the latest version of the Sysdig agent could solve this problem. For additional assistance contact support@sysdig.com with the output of uname -r"

CONFIG_FILE=/opt/draios/etc/dragent.yaml
if [ -e $CONFIG_FILE ]; then
	PRECONFIGURED=1
	echo "* Found preconfigured dragent.yaml"
else
	PRECONFIGURED=0
fi

if [ ! -z "$ACCESS_KEY" ]; then
	echo "* Setting access key"
	
	if ! grep ^customerid $CONFIG_FILE > /dev/null 2>&1; then
		echo "customerid: $ACCESS_KEY" >> $CONFIG_FILE
	else
		sed -i "s/^customerid.*/customerid: $ACCESS_KEY/g" $CONFIG_FILE
	fi
fi

if [ ! -z "$TAGS" ]; then
	echo "* Setting tags"

	if ! grep ^tags $CONFIG_FILE > /dev/null 2>&1; then
		echo "tags: $TAGS" >> $CONFIG_FILE
	else
		sed -i "s/^tags.*/tags: $TAGS/g" $CONFIG_FILE
	fi
fi

if [ ! -z "$COLLECTOR" ]; then
	echo "* Setting collector endpoint"

	if ! grep ^collector: $CONFIG_FILE > /dev/null 2>&1; then
		echo "collector: $COLLECTOR" >> $CONFIG_FILE
	else
		sed -i "s/^collector:.*/collector: $COLLECTOR/g" $CONFIG_FILE
	fi
fi

if [ ! -z "$COLLECTOR_PORT" ]; then
	echo "* Setting collector port"

	if ! grep ^collector_port $CONFIG_FILE > /dev/null 2>&1; then
		echo "collector_port: $COLLECTOR_PORT" >> $CONFIG_FILE
	else
		sed -i "s/^collector_port.*/collector_port: $COLLECTOR_PORT/g" $CONFIG_FILE
	fi
fi

if [ ! -z "$SECURE" ]; then
	echo "* Setting connection security"

	if ! grep ^ssl: $CONFIG_FILE > /dev/null 2>&1; then
		echo "ssl: $SECURE" >> $CONFIG_FILE
	else
		sed -i "s/^ssl:.*/ssl: $SECURE/g" $CONFIG_FILE
	fi
fi

if [ ! -z "$CHECK_CERTIFICATE" ]; then
	echo "* Setting SSL certificate check level"

	if ! grep ^ssl_verify_certificate $CONFIG_FILE > /dev/null 2>&1; then
		echo "ssl_verify_certificate: $CHECK_CERTIFICATE" >> $CONFIG_FILE
	else
		sed -i "s/^ssl_verify_certificate.*/ssl_verify_certificate: $CHECK_CERTIFICATE/g" $CONFIG_FILE
	fi
fi

if [ ! -z "$ADDITIONAL_CONF" ]; then
	if [ $PRECONFIGURED == 0 ]; then
		echo "* Setting additional customer configuration:"
		echo -e "$ADDITIONAL_CONF"
		echo -e "$ADDITIONAL_CONF" >> $CONFIG_FILE
	else
		echo "* ADDITIONAL_CONF ignored"
	fi
fi

if [ ! -z "$RUN_MODE" ]; then
	if ! grep ^run_mode: $CONFIG_FILE > /dev/null 2>&1; then
		echo "run_mode: $RUN_MODE" >> $CONFIG_FILE
	else
		sed -i "s/^run_mode:.*/run_mode: $RUN_MODE/g" $CONFIG_FILE
	fi
fi

mount_cgroup_subsys memory
mount_cgroup_subsys cpu
mount_cgroup_subsys cpuacct
mount_cgroup_subsys cpuset

if [ $# -eq 0 ]; then
    if [ "$SYSDIG_BUILD_KERNEL_MODULE" = "1" ]; then
	if [ "${RUN_MODE}" != "nodriver" ] && ! /opt/draios/bin/sysdigcloud-probe-loader "$KERNEL_ERR_MESSAGE"; then
		exit 1
	fi
    fi

    if [ -z "$SYSDIG_LAUNCH_DRAGENT" ] || [ "$SYSDIG_LAUNCH_DRAGENT" == 1 ]; then
	exec /opt/draios/bin/dragent --noipcns
    fi
else
	exec "$@"
fi
