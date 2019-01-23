include_directories(${DRAIOS_DEPENDENCIES_DIR}/protobuf-${DRAIOS_PROTOBUF_VERSION}/src)
include_directories(${CMAKE_BINARY_DIR}/userspace/draiosproto)

set(PROTOC_CMDLINE LD_LIBRARY_PATH=${DRAIOS_DEPENDENCIES_DIR}/protobuf-${DRAIOS_PROTOBUF_VERSION}/target/lib
                   ${DRAIOS_DEPENDENCIES_DIR}/protobuf-${DRAIOS_PROTOBUF_VERSION}/target/bin/protoc
                   -I ${PROJECT_SOURCE_DIR}/userspace/draiosproto)

add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/metrics_list.pb.cc
                          ${CMAKE_CURRENT_BINARY_DIR}/metrics_list.pb.h
	COMMENT "Building metrics_list cpp sources from .proto files"
	DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/metrics_list.proto
	DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/../../userspace/draiosproto/draios.proto
	COMMAND ${PROTOC_CMDLINE}
                --cpp_out=.
		--proto_path=${CMAKE_CURRENT_SOURCE_DIR}
		--proto_path=${CMAKE_CURRENT_SOURCE_DIR}/../../userspace/draiosproto
		${CMAKE_CURRENT_SOURCE_DIR}/metrics_list.proto
	WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

include_directories(${CMAKE_CURRENT_BINARY_DIR})

add_executable(diff_pb
	${CMAKE_CURRENT_BINARY_DIR}/metrics_list.pb.cc
	diff_pb.cpp)
	
target_link_libraries(diff_pb
	draiosproto)

install(TARGETS diff_pb
        DESTINATION ${CMAKE_INSTALL_PREFIX}/test/
        COMPONENT tests)
