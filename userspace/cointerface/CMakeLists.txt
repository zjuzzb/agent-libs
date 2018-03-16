set(BASE_GOPATH "${DRAIOS_DEPENDENCIES_DIR}/go")
set(GOPATH "${BASE_GOPATH}:${CMAKE_CURRENT_SOURCE_DIR}")
set(PROTOC_DIR "${DRAIOS_DEPENDENCIES_DIR}/protobuf-${DRAIOS_PROTOBUF_VERSION}/target")

# Create golang package directories for the generated go files
set(PROTO_OUT_DIR "${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface")
file(MAKE_DIRECTORY ${PROTO_OUT_DIR}/draiosproto)
file(MAKE_DIRECTORY ${PROTO_OUT_DIR}/sdc_internal)

add_custom_target(generate_proto ALL
  DEPENDS ${PROTO_OUT_DIR}/draiosproto/draios.pb.go
          ${PROTO_OUT_DIR}/sdc_internal/sdc_internal.pb.go)
add_custom_command(OUTPUT ${PROTO_OUT_DIR}/draiosproto/draios.pb.go
                          ${PROTO_OUT_DIR}/sdc_internal/sdc_internal.pb.go
        COMMAND GOPATH=${GOPATH} PATH="${BASE_GOPATH}/bin:${PROTOC_DIR}/bin:$ENV{PATH}" LD_LIBRARY_PATH="${PROTOC_DIR}/lib:$ENV{LD_LIBRARY_PATH}" PROTO_SRC_DIR="${CMAKE_CURRENT_SOURCE_DIR}/../draiosproto" PROTO_OUT_DIR="${PROTO_OUT_DIR}" go generate cointerface
        WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}
	DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/../draiosproto/sdc_internal.proto
	        ${CMAKE_CURRENT_SOURCE_DIR}/../draiosproto/draios.proto
		${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface/generate.go
		)

add_custom_target(cointerface ALL DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/cointerface)
add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/cointerface
#        COMMAND env GOPATH=${CMAKE_CURRENT_SOURCE_DIR} go fmt cointerface
        COMMAND env GOPATH=${GOPATH} go build -o "${CMAKE_CURRENT_BINARY_DIR}/cointerface" cointerface
        WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}
	DEPENDS generate_proto
	        ${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface/cointerface.go
                ${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface/server.go
                ${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface/swarm.go
		${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface/kubecollect/client.go
		${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface/kubecollect/daemonsets.go
		${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface/kubecollect/deployments.go
		${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface/kubecollect/pods.go
		${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface/kubecollect/namespaces.go
		${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface/kubecollect/nodes.go
		${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface/kubecollect/replicasets.go
		${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface/kubecollect/replicationcontrollers.go
		${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface/kubecollect/resourcequotas.go
		${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface/kubecollect/statefulsets.go
		${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface/kubecollect/services.go
		${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface/kubecollect/jobs.go
		${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface/kubecollect/cronjobs.go
		${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface/kubecollect/ingress.go
    )

# Note that we don't package the client. That's only for testing
# purposes.
install(DIRECTORY
	DESTINATION /opt/draios/run
	COMPONENT agent)

install(PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/cointerface
	DESTINATION ${DRAIOS_BIN_PREFIX}/bin
	COMPONENT agent)


