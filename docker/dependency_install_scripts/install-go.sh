#!/bin/bash
#usage install-go.sh <directory> <version> <url> <parallelism>

set -exo pipefail

DEPENDENCIES_DIR=$1
VERSION=$2
DEPENDENCIES_URL=$3
MAKE_JOBS=$4
GO_ARCHIVE_SHA256="f32501aeb8b7b723bc7215f6c373abb6981bbc7e1c7b44e9f07317e1a300dce2"

cd $DEPENDENCIES_DIR
GO_ARCHIVE="go$VERSION.linux-amd64.tar.gz"
wget $DEPENDENCIES_URL/$GO_ARCHIVE
# Verify the checksum of the archive
echo "$GO_ARCHIVE_SHA256  $GO_ARCHIVE" | sha256sum --check --status
# We use $DEPENDENCIES_DIR/go-$VERSION as GOROOT because $DEPENDENCIES_DIR/go
# was already taken for the GOPATH and they cannot coincide.
mkdir $DEPENDENCIES_DIR/go-$VERSION && tar -C $DEPENDENCIES_DIR/go-$VERSION -xzf $GO_ARCHIVE --strip-components 1
