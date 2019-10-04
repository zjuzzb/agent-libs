set(PROTOC_DIR "${DRAIOS_DEPENDENCIES_DIR}/protobuf-${DRAIOS_PROTOBUF_VERSION}/target")
set(GOPATH "${DRAIOS_DEPENDENCIES_DIR}/go")
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

# draiosproto can't be part of the GoGenerate auto-generated code because it
# has two outputs, rather than just the one.
add_custom_target(generate_draiosproto ALL
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/src/draiosproto/draios.pb.go
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/src/draiosproto/common.pb.go)
add_custom_command(OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/src/draiosproto/draios.pb.go
		   OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/src/draiosproto/common.pb.go
  COMMAND ${GOGENENV} PROTO_SRC_DIR="${CMAKE_CURRENT_SOURCE_DIR}/../draiosproto" go generate draiosproto
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/src/draiosproto
	DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/src/draiosproto/generate.go
                ${CMAKE_CURRENT_SOURCE_DIR}/src/draiosproto/go.mod
                ${CMAKE_CURRENT_SOURCE_DIR}/../draiosproto/draios.proto
                ${CMAKE_CURRENT_SOURCE_DIR}/../draiosproto/common.proto
                ${ARGN}
		)

function(GoGenerate target pbgofile)
add_custom_target(generate_${target} ALL
  DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/src/${target}/${pbgofile})
add_custom_command(OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/src/${target}/${pbgofile}
  COMMAND ${GOGENENV} PROTO_SRC_DIR="${CMAKE_CURRENT_SOURCE_DIR}/../draiosproto" go generate ${target}
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/src/${target}
	DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/src/${target}/generate.go
                ${CMAKE_CURRENT_SOURCE_DIR}/src/${target}/go.mod
                ${CMAKE_CURRENT_SOURCE_DIR}/../draiosproto/draios.proto
                ${CMAKE_CURRENT_SOURCE_DIR}/../draiosproto/common.proto
                ${ARGN}
		)
endfunction()

GoGenerate(sdc_internal sdc_internal.pb.go
                ${CMAKE_CURRENT_SOURCE_DIR}/../draiosproto/sdc_internal.proto
		)

GoGenerate(promex_pb promex.pb.go
                ${CMAKE_CURRENT_SOURCE_DIR}/../draiosproto/promex.proto
		)

GoBuild(cointerface
	        # Depend on both the target and its output file
	        ${CMAKE_CURRENT_SOURCE_DIR}/src/draiosproto/draios.pb.go
	        ${CMAKE_CURRENT_SOURCE_DIR}/src/draiosproto/common.pb.go
                generate_draiosproto
	        ${CMAKE_CURRENT_SOURCE_DIR}/src/sdc_internal/sdc_internal.pb.go
	        generate_sdc_internal
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
	        ${CMAKE_CURRENT_SOURCE_DIR}/src/draiosproto/draios.pb.go
	        ${CMAKE_CURRENT_SOURCE_DIR}/src/draiosproto/common.pb.go
                generate_draiosproto
	        ${CMAKE_CURRENT_SOURCE_DIR}/src/sdc_internal/sdc_internal.pb.go
	        generate_sdc_internal
	        ${CMAKE_CURRENT_SOURCE_DIR}/src/compclient/compclient.go
		${CMAKE_CURRENT_SOURCE_DIR}/src/install_prefix/install_prefix.go
	)

GoBuild(decode_proto
	        ${CMAKE_CURRENT_SOURCE_DIR}/src/draiosproto/draios.pb.go
	        ${CMAKE_CURRENT_SOURCE_DIR}/src/draiosproto/common.pb.go
                generate_draiosproto
	        ${CMAKE_CURRENT_SOURCE_DIR}/src/sdc_internal/sdc_internal.pb.go
	        generate_sdc_internal
	        ${CMAKE_CURRENT_SOURCE_DIR}/src/decode_proto/decode_proto.go
    )

GoBuild(promex
	        ${CMAKE_CURRENT_SOURCE_DIR}/src/draiosproto/draios.pb.go
	        ${CMAKE_CURRENT_SOURCE_DIR}/src/draiosproto/common.pb.go
                generate_draiosproto
	        ${CMAKE_CURRENT_SOURCE_DIR}/src/promex_pb/promex.pb.go
	        generate_promex_pb
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


