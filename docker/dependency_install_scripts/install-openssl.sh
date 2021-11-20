#!/bin/bash
#usage install-openssh.sh <directory> <version> <url> <parallelism>

set -exo pipefail

DEPENDENCIES_DIR=$1
VERSION=$2
DEPENDENCIES_URL=$3
MAKE_JOBS=$4

cd $DEPENDENCIES_DIR
wget $DEPENDENCIES_URL/openssl-$VERSION.tar.gz
tar -xzf openssl-$VERSION.tar.gz
cd openssl-$VERSION
./config shared --prefix=$DEPENDENCIES_DIR/openssl-$VERSION/target
make install

# Link /usr/include/openssl to dependencies, for correct version
ARCH=$(uname -m)
if [[ "$ARCH" == "s390x" ]]; then
	if [ -L /usr/include/openssl ]; then
		rm /usr/include/openssl
	elif [ -d /usr/include/openssl ]; then
		mv /usr/include/openssl /usr/include/openssl.orig
	fi
	ln -s $DEPENDENCIES_DIR/openssl-$VERSION/target/include/openssl /usr/include/openssl
fi
