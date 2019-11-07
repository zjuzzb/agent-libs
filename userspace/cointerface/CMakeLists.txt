set(PROTOC_DIR "${DRAIOS_DEPENDENCIES_DIR}/protobuf-${DRAIOS_PROTOBUF_VERSION}/target")
set(GOPATH "${DRAIOS_DEPENDENCIES_DIR}/go")
set(GEN_GO_DIR "${CMAKE_SOURCE_DIR}/build/generated-go")
# We should set GOPROXY=https://proxy.golang.org here but that breaks the
# docker/docker replace directive. Add it back later after upgrading docker.
set(GOENV scl enable rh-git29 -- env GOPATH=${GOPATH} GO111MODULE=on)
set(GOGENENV ${GOENV} PATH="${GOPATH}/bin:${PROTOC_DIR}/bin:$ENV{PATH}" LD_LIBRARY_PATH="${PROTOC_DIR}/lib:$ENV{LD_LIBRARY_PATH}")

function(GoBuild target)
add_custom_target(${target} ALL DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/${target})
add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/${target}
        COMMAND ${GOENV} go mod download
        COMMAND ${GOENV} GOPROXY=off go build -mod=readonly -o ${CMAKE_CURRENT_BINARY_DIR}/${target}
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/src/${target}
        DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/src/${target}/go.mod
		${ARGN}
	)
endfunction()

# Keep this version in sync with the various go.mod files
set(GOGO_PROTOBUF_VER "v1.3.1")
set(GOGO_PROTOBUF_PATH "github.com/gogo/protobuf/protoc-gen-gofast")
set(GOGO_PROTOBUF_DIR "${CMAKE_CURRENT_BINARY_DIR}/gogo_protobuf")
set(GOGO_PROTOBUF_VER_FILE "${GOGO_PROTOBUF_DIR}/${GOGO_PROTOBUF_VER}.txt")
add_custom_target(install_go_generate_deps ALL
	DEPENDS ${GOGO_PROTOBUF_VER_FILE})
add_custom_command(OUTPUT ${GOGO_PROTOBUF_VER_FILE}
	COMMAND ${CMAKE_COMMAND} -E remove_directory ${GOGO_PROTOBUF_DIR}
	COMMAND ${GOENV} go get ${GOGO_PROTOBUF_PATH}@${GOGO_PROTOBUF_VER}
	COMMAND ${CMAKE_COMMAND} -E make_directory ${GOGO_PROTOBUF_DIR}
	COMMAND ${CMAKE_COMMAND} -E touch ${GOGO_PROTOBUF_VER_FILE}
	)

# This function generate pb.go files for proto files that depend on
# draios.proto and common.proto. The generate_draiosproto target has
# an extra output pb.go, and that's handled by an optional argument.
# The ARGC/ARGV handling is hardcoded and will need fixing if the
# function signature changes.
function(GoGenerate target pbgofile protofile)
set(PROTO_SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../draiosproto")
set(GO_SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/src/${target}")
set(OUT_DIR "${GEN_GO_DIR}/${target}")
set(GO_MOD_DST "${OUT_DIR}/go.mod")
set(OUTFILES ${GO_MOD_DST} "${OUT_DIR}/${pbgofile}")
if(${ARGC} EQUAL 4)
	   list(APPEND OUTFILES "${OUT_DIR}/${ARGV3}")
endif()
file(MAKE_DIRECTORY ${OUT_DIR})
add_custom_target(generate_${target} ALL
        DEPENDS ${OUTFILES}
	)
add_custom_command(OUTPUT ${OUTFILES}
        COMMAND ${GOGENENV} PROTO_SRC_DIR="${PROTO_SRC_DIR}" PROTO_OUT_DIR="${OUT_DIR}" go generate ${target}
        COMMAND ${CMAKE_COMMAND} -E copy ${GO_SRC_DIR}/go.mod ${GO_MOD_DST}
        WORKING_DIRECTORY ${GO_SRC_DIR}
	DEPENDS ${GO_SRC_DIR}/generate.go
                ${GO_SRC_DIR}/go.mod
                ${PROTO_SRC_DIR}/draios.proto
                ${PROTO_SRC_DIR}/common.proto
                ${PROTO_SRC_DIR}/${protofile}
		)
set("${target}_deps" "generate_${target}" ${OUTFILES} PARENT_SCOPE)
endfunction()

GoGenerate(sdc_internal sdc_internal.pb.go sdc_internal.proto)
GoGenerate(promex_pb promex.pb.go promex.proto)
#Passing draios.proto is redundant but makes the function impl easier
GoGenerate(draiosproto draios.pb.go draios.proto common.pb.go)

GoBuild(cointerface
                ${draiosproto_deps}
	        ${sdc_internal_deps}
	        ${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface/cointerface.go
		${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface/compliance/docker_bench_scraper.go
		${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface/compliance/kube_bench_scraper.go
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
                ${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface/profile/profile.go
                ${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface/server.go
                ${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface/swarm.go
                ${CMAKE_CURRENT_SOURCE_DIR}/src/install_prefix/install_prefix.go
		)

add_custom_target(cointerface_test ALL DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/cointerface_test_success.txt)
add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/cointerface_test_success.txt
        COMMAND ${GOENV} GOPROXY=off go test -mod=readonly ./...
        COMMAND ${CMAKE_COMMAND} -E touch ${CMAKE_CURRENT_BINARY_DIR}/cointerface_test_success.txt
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface
	DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/cointerface
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
		${CMAKE_CURRENT_SOURCE_DIR}/src/test_helpers/assert.go
		)

GoBuild(compclient
                ${draiosproto_deps}
	        ${sdc_internal_deps}
	        ${CMAKE_CURRENT_SOURCE_DIR}/src/compclient/compclient.go
		${CMAKE_CURRENT_SOURCE_DIR}/src/install_prefix/install_prefix.go
	)

GoBuild(decode_proto
                ${draiosproto_deps}
	        ${sdc_internal_deps}
	        ${CMAKE_CURRENT_SOURCE_DIR}/src/decode_proto/decode_proto.go
    )

GoBuild(promex
                ${draiosproto_deps}
	        ${promex_pb_deps}
		${CMAKE_CURRENT_SOURCE_DIR}/src/heartbeat/heartbeat.go
		${CMAKE_CURRENT_SOURCE_DIR}/src/install_prefix/install_prefix.go
	        ${CMAKE_CURRENT_SOURCE_DIR}/src/promex/promex.go
	        ${CMAKE_CURRENT_SOURCE_DIR}/src/promex/server/server.go
    )

# Note that we don't package the client. That's only for testing
# purposes.
install(DIRECTORY
	DESTINATION ${CMAKE_INSTALL_PREFIX}/run
	COMPONENT agent-slim)

install(PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/cointerface
                 ${CMAKE_CURRENT_BINARY_DIR}/promex
	DESTINATION ${CMAKE_INSTALL_PREFIX}/bin
	COMPONENT agent-slim)

install(PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/decode_proto
	DESTINATION ${CMAKE_INSTALL_PREFIX}/bin
	COMPONENT tests)


