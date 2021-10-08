#!/bin/bash
#usage install-go.sh <directory> <version> <url> <parallelism> <go mods directory>

set -exo pipefail

DEPENDENCIES_DIR=$1
VERSION=$2
DEPENDENCIES_URL=$3
MAKE_JOBS=$4
GO_MODS_DIR=$5
GO_ARCHIVE_SHA256="f32501aeb8b7b723bc7215f6c373abb6981bbc7e1c7b44e9f07317e1a300dce2"

cd $DEPENDENCIES_DIR
GO_ARCHIVE="go$VERSION.linux-amd64.tar.gz"
GOROOT="$DEPENDENCIES_DIR/go-$VERSION"
wget $DEPENDENCIES_URL/$GO_ARCHIVE
# Verify the checksum of the archive
echo "$GO_ARCHIVE_SHA256  $GO_ARCHIVE" | sha256sum --check --status
# We use $DEPENDENCIES_DIR/go-$VERSION as GOROOT because $DEPENDENCIES_DIR/go
# was already taken for the GOPATH and they cannot coincide.
mkdir $GOROOT && tar -C $GOROOT -xzf $GO_ARCHIVE --strip-components 1

# Prefetch the modules from the go.mod files located in the children directories
# of GO_MODS_DIR, this will make sure that when the builder will be used the
# most of the modules needed during the go build will be already in the mod
# cache.
cd $GO_MODS_DIR
for mod_dir in $(find . -type d -maxdepth 1 -mindepth 1); do
    echo "Fetching dependencies of: $mod_dir"
    pushd $mod_dir
    # TODO(irozzo) sanitaze go.mod by removing references to local modules that
    # are not present during the build of the builder.
    [ -f go.mod ] && sed -i -e '/replace\ .\+\ \.\.\//d' \
        -e '/github\.com\/draios\//d' \
        -e '/protorepo\/agent-be\/proto/d' \
        go.mod
    $GOROOT/bin/go mod download -x
    popd
done
