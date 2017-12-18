include_directories(${DRAIOS_DEPENDENCIES_DIR}/grpc-${DRAIOS_GRPC_VERSION}/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/protobuf-${DRAIOS_PROTOBUF_VERSION}/target/include)

add_library(draiosproto STATIC
	${CMAKE_CURRENT_BINARY_DIR}/draios.pb.cc
	${CMAKE_CURRENT_BINARY_DIR}/sdc_internal.pb.cc
	${CMAKE_CURRENT_BINARY_DIR}/sdc_internal.grpc.pb.cc)

target_link_libraries(draiosproto
	${DRAIOS_DEPENDENCIES_DIR}/grpc-1.8.1/libs/opt/libgrpc++_unsecure.a
	${DRAIOS_DEPENDENCIES_DIR}/grpc-1.8.1/libs/opt/libgrpc_unsecure.a
	${DRAIOS_DEPENDENCIES_DIR}/c-ares-${DRAIOS_CARES_VERSION}/target/lib/libcares.a
	${DRAIOS_DEPENDENCIES_DIR}/protobuf-${DRAIOS_PROTOBUF_VERSION}/target/lib/libprotobuf.a
	pthread)

set(PROTOC_CMDLINE LD_LIBRARY_PATH=${DRAIOS_DEPENDENCIES_DIR}/protobuf-${DRAIOS_PROTOBUF_VERSION}/target/lib
                   ${DRAIOS_DEPENDENCIES_DIR}/protobuf-${DRAIOS_PROTOBUF_VERSION}/target/bin/protoc
                   -I ${PROJECT_SOURCE_DIR}/userspace/draiosproto)

add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/sdc_internal.pb.cc
                          ${CMAKE_CURRENT_BINARY_DIR}/sdc_internal.pb.h
                          ${CMAKE_CURRENT_BINARY_DIR}/sdc_internal.grpc.pb.cc
	                  ${CMAKE_CURRENT_BINARY_DIR}/sdc_internal.grpc.pb.h
	COMMENT "Building sdc_internal cpp sources from .proto files"
	DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/sdc_internal.proto ${CMAKE_CURRENT_SOURCE_DIR}/draios.proto
	COMMAND ${PROTOC_CMDLINE}
	        --cpp_out=.
		${CMAKE_CURRENT_SOURCE_DIR}/sdc_internal.proto
	COMMAND ${PROTOC_CMDLINE}
                --grpc_out=. --plugin=protoc-gen-grpc=${DRAIOS_DEPENDENCIES_DIR}/grpc-1.8.1/bins/opt/grpc_cpp_plugin
		${CMAKE_CURRENT_SOURCE_DIR}/sdc_internal.proto
	WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/draios.pb.cc
                          ${CMAKE_CURRENT_BINARY_DIR}/draios.pb.h
	COMMENT "Building draiosproto cpp sources from .proto files"
	DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/draios.proto
	COMMAND ${PROTOC_CMDLINE}
                --grpc_out=. --plugin=protoc-gen-grpc=${DRAIOS_DEPENDENCIES_DIR}/grpc-1.8.1/bins/opt/grpc_cpp_plugin
		${CMAKE_CURRENT_SOURCE_DIR}/sdc_internal.proto
	COMMAND ${PROTOC_CMDLINE}
                --cpp_out=.
		${CMAKE_CURRENT_SOURCE_DIR}/draios.proto
	WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

