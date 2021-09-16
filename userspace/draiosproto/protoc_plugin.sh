#!/bin/bash

# Executes protoc against a custom plugin. Really only expected
# to be necessary because of weird restrictions using cmake. If you can make this
# work without this wrapper, please do.
# $1 = protoc directory
# $2 = include dir for protobufs
# $3 = plugin
# $4 = output directory
# $5 = protobuf definition
#
# protobuf 3.18 doesn't support python 2. stick to 3.17
pip install 'protobuf<3.18'
echo "$1/protoc -I $2 --plugin=protoc-gen-custom=$3 --custom_out=$4 $5"
$1/protoc -I $2 --plugin=protoc-gen-custom=$3 --custom_out=$4 $5
