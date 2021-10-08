//go:build tools
// +build tools

// https://github.com/golang/go/wiki/Modules#how-can-i-track-tool-dependencies-for-a-module
package tools

import (
	_ "github.com/gogo/protobuf/protoc-gen-gofast"
)
