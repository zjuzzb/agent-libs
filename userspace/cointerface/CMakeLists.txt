set(BASE_GOPATH "${DRAIOS_DEPENDENCIES_DIR}/go")
set(GOPATH "${BASE_GOPATH}:${CMAKE_CURRENT_SOURCE_DIR}")
set(PROTOC_DIR "${DRAIOS_DEPENDENCIES_DIR}/protobuf-${DRAIOS_PROTOBUF_VERSION}/target")

# Create golang package directories for the generated go files
set(COINTERFACE_OUT_DIR "${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface")
set(DECODEPROTO_OUT_DIR "${CMAKE_CURRENT_SOURCE_DIR}/src/decode_proto")
set(COMPCLIENT_OUT_DIR "${CMAKE_CURRENT_SOURCE_DIR}/src/compclient")
set(PROMEX_OUT_DIR "${CMAKE_CURRENT_SOURCE_DIR}/src/promex")
file(MAKE_DIRECTORY ${COINTERFACE_OUT_DIR}/draiosproto)
file(MAKE_DIRECTORY ${COINTERFACE_OUT_DIR}/sdc_internal)
file(MAKE_DIRECTORY ${DECODEPROTO_OUT_DIR}/draiosproto)
file(MAKE_DIRECTORY ${DECODEPROTO_OUT_DIR}/sdc_internal)
file(MAKE_DIRECTORY ${COMPCLIENT_OUT_DIR}/draiosproto)
file(MAKE_DIRECTORY ${COMPCLIENT_OUT_DIR}/sdc_internal)
file(MAKE_DIRECTORY ${PROMEX_OUT_DIR}/draiosproto)
file(MAKE_DIRECTORY ${PROMEX_OUT_DIR}/promex_pb)

add_custom_target(generate_cointerface_proto ALL
  DEPENDS ${COINTERFACE_OUT_DIR}/draiosproto/draios.pb.go
          ${COINTERFACE_OUT_DIR}/sdc_internal/sdc_internal.pb.go)
add_custom_command(OUTPUT ${COINTERFACE_OUT_DIR}/draiosproto/draios.pb.go
                          ${COINTERFACE_OUT_DIR}/sdc_internal/sdc_internal.pb.go
  COMMAND GOPATH=${GOPATH} PATH="${BASE_GOPATH}/bin:${PROTOC_DIR}/bin:$ENV{PATH}" LD_LIBRARY_PATH="${PROTOC_DIR}/lib:$ENV{LD_LIBRARY_PATH}" PROTO_SRC_DIR="${CMAKE_CURRENT_SOURCE_DIR}/../draiosproto" PROTO_OUT_DIR="${COINTERFACE_OUT_DIR}" go generate cointerface
        WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}
	DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/../draiosproto/sdc_internal.proto
	        ${CMAKE_CURRENT_SOURCE_DIR}/../draiosproto/draios.proto
		${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface/generate.go
		)

add_custom_target(generate_decode_proto_proto ALL
  DEPENDS ${DECODEPROTO_OUT_DIR}/draiosproto/draios.pb.go
          ${DECODEPROTO_OUT_DIR}/sdc_internal/sdc_internal.pb.go)
add_custom_command(OUTPUT ${DECODEPROTO_OUT_DIR}/draiosproto/draios.pb.go
                          ${DECODEPROTO_OUT_DIR}/sdc_internal/sdc_internal.pb.go
  COMMAND GOPATH=${GOPATH} PATH="${BASE_GOPATH}/bin:${PROTOC_DIR}/bin:$ENV{PATH}" LD_LIBRARY_PATH="${PROTOC_DIR}/lib:$ENV{LD_LIBRARY_PATH}" PROTO_SRC_DIR="${CMAKE_CURRENT_SOURCE_DIR}/../draiosproto" PROTO_OUT_DIR="${DECODEPROTO_OUT_DIR}" go generate decode_proto
        WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}
	DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/../draiosproto/sdc_internal.proto
	        ${CMAKE_CURRENT_SOURCE_DIR}/../draiosproto/draios.proto
		${CMAKE_CURRENT_SOURCE_DIR}/src/decode_proto/generate.go
		)

add_custom_target(generate_compclient_proto ALL
  DEPENDS ${COMPCLIENT_OUT_DIR}/draiosproto/draios.pb.go
          ${COMPCLIENT_OUT_DIR}/sdc_internal/sdc_internal.pb.go)
add_custom_command(OUTPUT ${COMPCLIENT_OUT_DIR}/draiosproto/draios.pb.go
                          ${COMPCLIENT_OUT_DIR}/sdc_internal/sdc_internal.pb.go
			  COMMAND GOPATH=${GOPATH} PATH="${BASE_GOPATH}/bin:${PROTOC_DIR}/bin:$ENV{PATH}" LD_LIBRARY_PATH="${PROTOC_DIR}/lib:$ENV{LD_LIBRARY_PATH}" PROTO_SRC_DIR="${CMAKE_CURRENT_SOURCE_DIR}/../draiosproto" PROTO_OUT_DIR="${COMPCLIENT_OUT_DIR}" go generate compclient
	DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/../draiosproto/sdc_internal.proto
	        ${CMAKE_CURRENT_SOURCE_DIR}/../draiosproto/draios.proto
		${CMAKE_CURRENT_SOURCE_DIR}/src/compclient/generate.go
		)

add_custom_target(generate_promex_proto ALL
  DEPENDS ${PROMEX_OUT_DIR}/draiosproto/draios.pb.go
          ${PROMEX_OUT_DIR}/promex_pb/promex.pb.go)
add_custom_command(OUTPUT ${PROMEX_OUT_DIR}/draiosproto/draios.pb.go
                          ${PROMEX_OUT_DIR}/promex_pb/promex.pb.go
			  COMMAND GOPATH=${GOPATH} PATH="${BASE_GOPATH}/bin:${PROTOC_DIR}/bin:$ENV{PATH}" LD_LIBRARY_PATH="${PROTOC_DIR}/lib:$ENV{LD_LIBRARY_PATH}" PROTO_SRC_DIR="${CMAKE_CURRENT_SOURCE_DIR}/../draiosproto" PROTO_OUT_DIR="${PROMEX_OUT_DIR}" go generate promex
	DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/../draiosproto/promex.proto
	        ${CMAKE_CURRENT_SOURCE_DIR}/../draiosproto/draios.proto
		${CMAKE_CURRENT_SOURCE_DIR}/src/promex/generate.go
		)

add_custom_target(cointerface ALL DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/cointerface)
add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/cointerface
#        COMMAND env GOPATH=${CMAKE_CURRENT_SOURCE_DIR} go fmt cointerface
        COMMAND env GOPATH=${GOPATH} go test cointerface/...
        COMMAND env GOPATH=${GOPATH} go build -o "${CMAKE_CURRENT_BINARY_DIR}/cointerface" cointerface
        WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}
	DEPENDS generate_cointerface_proto
	        ${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface/cointerface.go
                ${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface/server.go
                ${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface/profile/profile.go
                ${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface/swarm.go
		${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface/compliance/docker_bench_scraper.go
		${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface/compliance/kube_bench_scraper.go
		${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface/compliance/test_module_scraper.go
		${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface/compliance/module_mgr.go
		${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface/compliance/module.go
		${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface/kubecollect/client.go
		${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface/kubecollect/client_test.go
		${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface/kubecollect/daemonsets.go
		${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface/kubecollect/deployments.go
		${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface/kubecollect/deployments_test.go
		${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface/kubecollect/pods.go
		${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface/kubecollect/pods_test.go
		${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface/kubecollect/namespaces.go
		${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface/kubecollect/nodes.go
		${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface/kubecollect/nodes_test.go
		${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface/kubecollect/replicasets.go
		${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface/kubecollect/replicasets_test.go
		${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface/kubecollect/replicationcontrollers.go
		${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface/kubecollect/resourcequotas.go
		${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface/kubecollect/resourcequotas_test.go
		${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface/kubecollect/statefulsets.go
		${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface/kubecollect/services.go
		${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface/kubecollect/jobs.go
		${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface/kubecollect/cronjobs.go
		${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface/kubecollect/ingress.go
		${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface/kubecollect/horizontalpodautoscalers.go
		)

add_custom_target(compclient ALL DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/compclient)
add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/compclient
        COMMAND env GOPATH=${GOPATH} go build -o "${CMAKE_CURRENT_BINARY_DIR}/compclient" compclient
        WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}
	DEPENDS generate_compclient_proto
	        ${CMAKE_CURRENT_SOURCE_DIR}/src/compclient/compclient.go
	)

add_custom_target(decode_proto ALL DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/decode_proto)
add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/decode_proto
#        COMMAND env GOPATH=${CMAKE_CURRENT_SOURCE_DIR} go fmt decode_proto
        COMMAND env GOPATH=${GOPATH} go build -o "${CMAKE_CURRENT_BINARY_DIR}/decode_proto" decode_proto
        WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}
	DEPENDS generate_cointerface_proto
	        ${CMAKE_CURRENT_SOURCE_DIR}/src/decode_proto/decode_proto.go
    )

add_custom_target(promex ALL DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/promex)
add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/promex
        COMMAND env GOPATH=${GOPATH} go build -o "${CMAKE_CURRENT_BINARY_DIR}/promex" promex
        WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}
	DEPENDS generate_promex_proto
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


