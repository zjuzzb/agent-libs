#!/usr/bin/env bash
#
# This script is intended to be used for compiling the Go binaries for local
# testing only.

set -euo pipefail

display_usage() {
    echo "Please provide the path to the protorepo."
    echo -e "\nUsage: ${0} [protorepo_path] \n"
    exit 1
}

[ $# -eq 0 ] && display_usage
PROTOREPO_ROOT=${1}

# Check dependencies
echo "Checking dependencies"
command -v protoc &> /dev/null || \
    { echo "Please install protoc before running"; exit 1; }
command -v protoc-gen-gofast &> /dev/null || \
    { echo "Please install protoc-gen-gofast before running"; exit 1; }
echo "ok"

# The root of the agent repository
AGENT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
BUILD_DIR="${AGENT_ROOT}/build"
PROTO_DIR="${BUILD_DIR}/proto"
GENERATED_GO_DIR="${BUILD_DIR}/generated-go"

mkdir -p "${GENERATED_GO_DIR}/"{draiosproto,promex_pb,sdc_internal}
mkdir -p "${PROTO_DIR}"
"${PROTOREPO_ROOT}/agent-be/cpp/preproc.sh" "${PROTO_DIR}"

echo "Generating go model"
echo "Generating draiosproto"
cd "${AGENT_ROOT}/userspace/cointerface/src/draiosproto/" && \
    PROTO_OUT_DIR="${BUILD_DIR}/generated-go/draiosproto/" \
    PROTO_SRC_DIR="${AGENT_ROOT}/userspace/draiosproto/" \
    PROTO_BIN_DIR="${PROTO_DIR}" go generate draiosproto
cp "${AGENT_ROOT}/userspace/cointerface/src/draiosproto/go.mod" \
    "${BUILD_DIR}/generated-go/draiosproto/protorepo/agent-be/proto/"
echo "ok"
echo "Generating promex_pb"
cd "${AGENT_ROOT}/userspace/cointerface/src/promex_pb/" && \
    PROTO_OUT_DIR="${BUILD_DIR}/generated-go/promex_pb/" \
    PROTO_SRC_DIR="${AGENT_ROOT}/userspace/draiosproto/" \
    PROTO_BIN_DIR="${PROTO_DIR}" go generate promex_pb
cp "${AGENT_ROOT}/userspace/cointerface/src/promex_pb/go.mod" \
    "${BUILD_DIR}/generated-go/promex_pb/"
echo "ok"
echo "Generating sdc_internal"
cd "${AGENT_ROOT}/userspace/cointerface/src/sdc_internal/" && \
    PROTO_OUT_DIR="${BUILD_DIR}/generated-go/sdc_internal/" \
    PROTO_SRC_DIR="${AGENT_ROOT}/userspace/draiosproto/" \
    PROTO_BIN_DIR="${PROTO_DIR}" go generate sdc_internal
cp "${AGENT_ROOT}/userspace/cointerface/src/sdc_internal/go.mod" \
    "${BUILD_DIR}/generated-go/sdc_internal/"
echo "ok"
