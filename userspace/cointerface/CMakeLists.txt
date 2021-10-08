# When GOROOT is defined it takes precedence over the default version.
if (NOT DEFINED GOROOT)
    set(GOROOT "${DRAIOS_DEPENDENCIES_DIR}/go-${DRAIOS_GO_VERSION}")
endif()
if (NOT DEFINED GOPATH)
    set(GOPATH "${DRAIOS_DEPENDENCIES_DIR}/go")
endif()

set(PROTOC_DIR "${DRAIOS_DEPENDENCIES_DIR}/protobuf-${DRAIOS_PROTOBUF_VERSION}/target")
set(GEN_GO_DIR "${CMAKE_SOURCE_DIR}/build/generated-go")
set(GOENV env GOROOT=${GOROOT} GOPATH=${GOPATH})

set(GOGENENV ${GOENV} PATH="${GOPATH}/bin:${PROTOC_DIR}/bin:$ENV{PATH}"
             LD_LIBRARY_PATH="${PROTOC_DIR}/lib:$ENV{LD_LIBRARY_PATH}"
)

function(GoBuild target)
    add_custom_target(${target} ALL DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/${target})
    add_custom_command(
        OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/${target}
        COMMAND ${GOENV} ${GOROOT}/bin/go build -mod=readonly -trimpath -o ${CMAKE_CURRENT_BINARY_DIR}/${target}
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/src/${target}
        DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/src/${target}/go.mod ${ARGN}
    )
endfunction()

function(GoInstall name mod moddir cgo_enabled)
    add_custom_target(goinstall-${name}
        COMMAND ${GOENV} CGO_ENABLED=${cgo_enabled} ${GOROOT}/bin/go install ${mod}
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/src/${moddir}
        DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/src/${moddir}/go.mod ${ARGN}
    )
endfunction()

function(GoLint target)
    add_custom_target(golint-${target} ALL
        COMMAND ${GOENV} PATH="${GOROOT}/bin:$ENV{PATH}" ${GOPATH}/bin/golangci-lint run -v --allow-parallel-runners --timeout=5m
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/src/${target}
        DEPENDS goinstall-golangci-lint ${ARGN}
    )
endfunction()

set(PROTO_SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../draiosproto")
set(PROTO_BIN_DIR "${CMAKE_CURRENT_BINARY_DIR}/../draiosproto")
# This function generate pb.go files for proto files that depend on draios.proto and common.proto.
# The generate_draiosproto target has an extra output pb.go, and that's handled by an optional
# argument. The ARGC/ARGV handling is hardcoded and will need fixing if the function signature
# changes.
function(GoGenerate target folder pbgofile protofile)

    set(GO_SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/src/${target}")
    set(OUT_DIR "${GEN_GO_DIR}/${target}")
    set(GO_MOD_DST "${GEN_GO_DIR}/${folder}")
    set(OUTFILES ${GO_MOD_DST} "${OUT_DIR}/${pbgofile}")
    if(${ARGC} EQUAL 5)
        list(APPEND OUTFILES "${OUT_DIR}/${ARGV4}")
    endif()
    file(MAKE_DIRECTORY ${OUT_DIR})
    add_custom_target(generate_${target} ALL DEPENDS ${OUTFILES})
    add_custom_command(
        OUTPUT ${OUTFILES}
        COMMAND ${CMAKE_COMMAND} -E make_directory ${OUT_DIR}
        COMMAND ${GOGENENV} PROTO_SRC_DIR="${PROTO_SRC_DIR}" PROTO_BIN_DIR="${PROTO_BIN_DIR}"
                PROTO_OUT_DIR="${OUT_DIR}" ${GOROOT}/bin/go generate ${target}
        COMMAND ${CMAKE_COMMAND} -E copy ${GO_SRC_DIR}/go.mod ${GO_MOD_DST}
        WORKING_DIRECTORY ${GO_SRC_DIR}
        DEPENDS ${GO_SRC_DIR}/generate.go
                ${GO_SRC_DIR}/go.mod
                ${PROTO_BIN_DIR}/draios.proto
                ${PROTO_BIN_DIR}/common.proto
                ${protofile}
                ${GOGO_PROTOBUF_VER_FILE}
                preproc_proto
                goinstall-protoc-gen-gofast
    )
    set("${target}_deps"
        "generate_${target}" ${OUTFILES}
        PARENT_SCOPE
    )
endfunction()

goinstall(
    golangci-lint
    github.com/golangci/golangci-lint/cmd/golangci-lint
    tools
    0
)
goinstall(
    protoc-gen-gofast
    github.com/gogo/protobuf/protoc-gen-gofast
    tools
    1
)

gogenerate(sdc_internal sdc_internal sdc_internal.pb.go ${PROTO_SRC_DIR}/sdc_internal.proto)
gogenerate(promex_pb promex_pb promex.pb.go ${PROTO_SRC_DIR}/promex.proto)
# Passing draios.proto is redundant but makes the function impl easier. The draios.proto and
# common.proto files have the go_package option set so we need to redirect the go.mod into that
# folder.
gogenerate(
    draiosproto draiosproto/protorepo/agent-be/proto draios.pb.go ${PROTO_BIN_DIR}/draios.proto
    common.pb.go
)

gobuild(
    cointerface
    ${draiosproto_deps}
    ${sdc_internal_deps}
    ${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface/cointerface.go
    ${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface/compliance/docker_bench_scraper.go
    ${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface/compliance/kube_bench_scraper.go
    ${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface/compliance/linux_bench_scraper.go
    ${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface/compliance/module.go
    ${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface/compliance/module_mgr.go
    ${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface/compliance/test_module_scraper.go
    ${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface/k8s_audit/module.go
    ${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface/kubecollect/client.go
    ${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface/kubecollect/cronjobs.go
    ${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface/kubecollect/daemonsets.go
    ${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface/kubecollect/deployments.go
    ${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface/kubecollect/events.go
    ${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface/kubecollect/horizontalpodautoscalers.go
    ${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface/kubecollect/ingress.go
    ${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface/kubecollect/jobs.go
    ${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface/kubecollect/pod_aggregate_status_counter.go
    ${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface/kubecollect/namespaces.go
    ${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface/kubecollect/nodes.go
    ${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface/kubecollect/persistentvolumeclaims.go
    ${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface/kubecollect/persistentvolumes.go
    ${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface/kubecollect/pods.go
    ${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface/kubecollect/replicasets.go
    ${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface/kubecollect/replicationcontrollers.go
    ${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface/kubecollect/resourcequotas.go
    ${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface/kubecollect/selector_cache.go
    ${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface/kubecollect/services.go
    ${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface/kubecollect/statefulsets.go
    ${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface/kubecollect_common/client.go
    ${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface/kubecollect_common/delegate.go
    ${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface/kubecollect_common/kubecollect_interface.go
    ${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface/kubecollect_tc/client.go
    ${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface/kubecollect_tc/daemonsets.go
    ${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface/kubecollect_tc/deployments.go
    ${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface/kubecollect_tc/horizontalpodautoscalers.go
    ${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface/kubecollect_tc/jobs.go
    ${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface/kubecollect_tc/nodes.go
    ${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface/kubecollect_tc/pods.go
    ${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface/kubecollect_tc/replicasets.go
    ${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface/kubecollect_tc/replicationcontrollers.go
    ${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface/kubecollect_tc/services.go
    ${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface/kubecollect_tc/statefulsets.go
    ${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface/profile/profile.go
    ${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface/server.go
    ${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface/swarm.go
    ${CMAKE_CURRENT_SOURCE_DIR}/src/install_prefix/install_prefix.go
)

golint(
    cointerface
    ${draiosproto_deps}
    ${sdc_internal_deps}
)

add_custom_target(
    cointerface_test ALL DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/cointerface_test_success.txt
)
add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/cointerface_test_success.txt
    COMMAND ${GOENV} ${GOROOT}/bin/go test -mod=readonly ./...
    COMMAND ${CMAKE_COMMAND} -E touch ${CMAKE_CURRENT_BINARY_DIR}/cointerface_test_success.txt
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface
    DEPENDS
        ${CMAKE_CURRENT_BINARY_DIR}/cointerface
        cointerface
        ${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface/kubecollect/client_test.go
        ${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface/kubecollect/deployments_test.go
        ${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface/kubecollect/events_test.go
        ${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface/kubecollect/nodes_test.go
        ${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface/kubecollect/persistentvolumeclaim_test.go
        ${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface/kubecollect/persistentvolume_test.go
        ${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface/kubecollect/pods_test.go
        ${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface/kubecollect/replicasets_test.go
        ${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface/kubecollect/resourcequotas_test.go
        ${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface/kubecollect/selector_cache_test.go
        ${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface/kubecollect/pod_aggregate_status_counter_test.go
        ${CMAKE_CURRENT_SOURCE_DIR}/src/test_helpers/assert.go
)

gobuild(compclient ${draiosproto_deps} ${sdc_internal_deps}
        ${CMAKE_CURRENT_SOURCE_DIR}/src/compclient/compclient.go
        ${CMAKE_CURRENT_SOURCE_DIR}/src/install_prefix/install_prefix.go
)

gobuild(decode_proto ${draiosproto_deps} ${sdc_internal_deps}
        ${CMAKE_CURRENT_SOURCE_DIR}/src/decode_proto/decode_proto.go
)

gobuild(
    promex
    ${draiosproto_deps}
    ${promex_pb_deps}
    ${CMAKE_CURRENT_SOURCE_DIR}/src/heartbeat/heartbeat.go
    ${CMAKE_CURRENT_SOURCE_DIR}/src/install_prefix/install_prefix.go
    ${CMAKE_CURRENT_SOURCE_DIR}/src/promex/promex.go
    ${CMAKE_CURRENT_SOURCE_DIR}/src/promex/server/server.go
)

gobuild(
    lease_pool_manager
    ${draiosproto_deps}
    ${sdc_internal_deps}
    ${CMAKE_CURRENT_SOURCE_DIR}/src/lease_pool_manager/leader_lib/lease_pool_manager.go
    ${CMAKE_CURRENT_SOURCE_DIR}/src/lease_pool_manager/leader_lib/lease.go
    ${CMAKE_CURRENT_SOURCE_DIR}/src/lease_pool_manager/main.go
    ${CMAKE_CURRENT_SOURCE_DIR}/src/lease_pool_manager/server/server.go
    ${CMAKE_CURRENT_SOURCE_DIR}/src/lease_pool_manager/go.mod
)

gobuild(
    coclient
    ${draiosproto_deps}
    ${sdc_internal_deps}
    ${CMAKE_CURRENT_SOURCE_DIR}/src/coclient/coclient.go
)

golint(
    coclient
    ${draiosproto_deps}
    ${sdc_internal_deps}
)

add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/cs_client_test
    COMMAND ${GOENV} ${GOROOT}/bin/go build -o ${CMAKE_CURRENT_BINARY_DIR}/cs_client_test
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/src/lease_pool_manager/test
    DEPENDS ${draiosproto_deps} ${sdc_internal_deps}
            ${CMAKE_CURRENT_SOURCE_DIR}/src/lease_pool_manager/go.mod
            ${CMAKE_CURRENT_SOURCE_DIR}/src/lease_pool_manager/test/test_client.go
)

add_custom_target(cs_test_client ALL DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/cs_client_test)

# Note that we don't package the client. That's only for testing purposes.
install(
    DIRECTORY
    DESTINATION ${CMAKE_INSTALL_PREFIX}/run
    COMPONENT agent-slim
)

install(
    PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/cointerface ${CMAKE_CURRENT_BINARY_DIR}/promex
             ${CMAKE_CURRENT_BINARY_DIR}/lease_pool_manager
    DESTINATION ${CMAKE_INSTALL_PREFIX}/bin
    COMPONENT agent-slim
)

install(
    DIRECTORY
    DESTINATION ${CMAKE_INSTALL_PREFIX}/run
    COMPONENT agentone
)

install(
    PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/cointerface
    DESTINATION ${CMAKE_INSTALL_PREFIX}/bin
    COMPONENT agentone
)

install(
    DIRECTORY
    DESTINATION ${CMAKE_INSTALL_PREFIX}/run
    COMPONENT agentino
)

install(
    PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/cointerface
    DESTINATION ${CMAKE_INSTALL_PREFIX}/bin
    COMPONENT agentino
)

install(
    PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/decode_proto
    DESTINATION ${CMAKE_INSTALL_PREFIX}/bin
    COMPONENT tests
)

install(
    PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/cs_client_test
    DESTINATION ${CMAKE_INSTALL_PREFIX}/bin
    COMPONENT tests
)
