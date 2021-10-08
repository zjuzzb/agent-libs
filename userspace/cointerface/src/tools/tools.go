//go:build tools
// +build tools

// Package tools is used to track binary dependencies with go modules
// https://github.com/golang/go/wiki/Modules#how-can-i-track-tool-dependencies-for-a-module
package tools

import (
	// linting tools
	_ "github.com/golangci/golangci-lint/cmd/golangci-lint"

	// protoc go plugin
	_ "github.com/gogo/protobuf/protoc-gen-gofast"
)
