//go:build tools
// +build tools

// "go mod" is not correctly recording this indirect dependency for some reason,
// so follow the suggestion for recording module tool versions in order to force
// go mod to record it
// https://github.com/golang/go/wiki/Modules#how-can-i-track-tool-dependencies-for-a-module
package tools

import (
	_ "github.com/golang/protobuf/proto"
)
