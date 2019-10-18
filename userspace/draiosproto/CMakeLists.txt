include_directories(${DRAIOS_DEPENDENCIES_DIR}/grpc-${DRAIOS_GRPC_VERSION}/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/protobuf-${DRAIOS_PROTOBUF_VERSION}/target/include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../libsanalyzer/src) # for tdigest

if(NOT CYGWIN)
	add_library(draiosproto STATIC
		${CMAKE_CURRENT_BINARY_DIR}/aggregator_overrides.cpp
		${CMAKE_CURRENT_BINARY_DIR}/aggregator_limits.cpp
		${CMAKE_CURRENT_BINARY_DIR}/draios.pb.cc
		${CMAKE_CURRENT_BINARY_DIR}/common.pb.cc
		${CMAKE_CURRENT_BINARY_DIR}/tap.pb.cc
		${CMAKE_CURRENT_BINARY_DIR}/secure.pb.cc
		${CMAKE_CURRENT_BINARY_DIR}/sdc_internal.pb.cc
		${CMAKE_CURRENT_BINARY_DIR}/sdc_internal.grpc.pb.cc
		${CMAKE_CURRENT_BINARY_DIR}/promex.pb.cc
		${CMAKE_CURRENT_BINARY_DIR}/promex.grpc.pb.cc
		${CMAKE_CURRENT_BINARY_DIR}/draios.proto_builder.cpp)
else()
	add_library(draiosproto STATIC
		${CMAKE_CURRENT_BINARY_DIR}/draios.pb.cc
		${CMAKE_CURRENT_BINARY_DIR}/common.pb.cc
		${CMAKE_CURRENT_BINARY_DIR}/sdc_internal.pb.cc
		${CMAKE_CURRENT_BINARY_DIR}/sdc_internal.grpc.pb.cc
		${CMAKE_CURRENT_BINARY_DIR}/draios.proto_builder.cpp)
endif()
if(NOT CYGWIN)
target_link_libraries(draiosproto
	${DRAIOS_DEPENDENCIES_DIR}/grpc-${DRAIOS_GRPC_VERSION}/libs/opt/libgrpc++_unsecure.a
	${DRAIOS_DEPENDENCIES_DIR}/grpc-${DRAIOS_GRPC_VERSION}/libs/opt/libgrpc_unsecure.a
	${DRAIOS_DEPENDENCIES_DIR}/c-ares-${DRAIOS_CARES_VERSION}/target/lib/libcares.a
	${DRAIOS_DEPENDENCIES_DIR}/protobuf-${DRAIOS_PROTOBUF_VERSION}/target/lib/libprotobuf.a
	${DRAIOS_DEPENDENCIES_DIR}/zlib-${DRAIOS_ZLIB_VERSION}/libz.a
	pthread)
else()
target_link_libraries(draiosproto
	${DRAIOS_DEPENDENCIES_DIR}/protobuf-${DRAIOS_PROTOBUF_VERSION}/target/lib/libprotobuf.a)
endif()

set(PROTOC_CMDLINE LD_LIBRARY_PATH=${DRAIOS_DEPENDENCIES_DIR}/protobuf-${DRAIOS_PROTOBUF_VERSION}/target/lib
                   ${DRAIOS_DEPENDENCIES_DIR}/protobuf-${DRAIOS_PROTOBUF_VERSION}/target/bin/protoc
                   -I ${PROJECT_SOURCE_DIR}/userspace/draiosproto)

if(NOT CYGWIN)
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
                --grpc_out=. --plugin=protoc-gen-grpc=${DRAIOS_DEPENDENCIES_DIR}/grpc-${DRAIOS_GRPC_VERSION}/bins/opt/grpc_cpp_plugin
		${CMAKE_CURRENT_SOURCE_DIR}/sdc_internal.proto
	WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
endif()

if(NOT CYGWIN)
add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/draios.pb.cc
                          ${CMAKE_CURRENT_BINARY_DIR}/draios.pb.h
                          ${CMAKE_CURRENT_BINARY_DIR}/common.pb.h
                          ${CMAKE_CURRENT_BINARY_DIR}/common.pb.cc
	COMMENT "Building draiosproto cpp sources from .proto files"
	DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/draios.proto
	COMMAND ${PROTOC_CMDLINE}
                --grpc_out=. --plugin=protoc-gen-grpc=${DRAIOS_DEPENDENCIES_DIR}/grpc-${DRAIOS_GRPC_VERSION}/bins/opt/grpc_cpp_plugin
		${CMAKE_CURRENT_SOURCE_DIR}/sdc_internal.proto
	COMMAND ${PROTOC_CMDLINE}
                --cpp_out=.
		${CMAKE_CURRENT_SOURCE_DIR}/draios.proto
	COMMAND ${PROTOC_CMDLINE}
                --cpp_out=.
		${CMAKE_CURRENT_SOURCE_DIR}/common.proto
	WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
else()
add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/draios.pb.cc
                          ${CMAKE_CURRENT_BINARY_DIR}/draios.pb.h
                          ${CMAKE_CURRENT_BINARY_DIR}/common.pb.h
                          ${CMAKE_CURRENT_BINARY_DIR}/common.pb.cc
	COMMENT "Building draiosproto cpp sources from .proto files"
	DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/draios.proto
	COMMAND ${PROTOC_CMDLINE}
                --cpp_out=.
		${CMAKE_CURRENT_SOURCE_DIR}/draios.proto
	COMMAND ${PROTOC_CMDLINE}
                --cpp_out=.
		${CMAKE_CURRENT_SOURCE_DIR}/common.proto
	WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
endif()

file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/aggregator_overrides.h
     DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/aggregator_overrides.cpp
     DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/aggregator_limits.cpp
     DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/aggregator_base.h
     DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/draios_proto_extension.py
     DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/aggr_pbs
        DESTINATION ${CMAKE_INSTALL_PREFIX}/test)
add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/draios.proto_builder.cpp
	                  ${CMAKE_CURRENT_BINARY_DIR}/draios.proto_builder.h
			  ${CMAKE_CURRENT_BINARY_DIR}/draios.proto.h
	COMMENT "Building aggregator sources from .proto files"
	DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/draios.proto
	DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/common.proto
	DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/draios-aggregator-plugin.py
	DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/draios_proto_extension.py
	DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/protoc_plugin.sh
	COMMAND scl enable python27 "${CMAKE_CURRENT_SOURCE_DIR}/protoc_plugin.sh ${DRAIOS_DEPENDENCIES_DIR}/protobuf-${DRAIOS_PROTOBUF_VERSION}/target/bin/ ${PROJECT_SOURCE_DIR}/userspace/draiosproto ${CMAKE_CURRENT_SOURCE_DIR}/draios-aggregator-plugin.py ${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/draios.proto"
	WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

if(NOT CYGWIN)
add_custom_command(
		OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/tap.pb.cc
		       ${CMAKE_CURRENT_BINARY_DIR}/tap.pb.h
		COMMENT "Building tap cpp sources from .proto files"
		DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/tap.proto
		COMMAND ${PROTOC_CMDLINE} --cpp_out=. ${CMAKE_CURRENT_SOURCE_DIR}/tap.proto
		WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

add_custom_command(
		OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/secure.pb.cc
		${CMAKE_CURRENT_BINARY_DIR}/secure.pb.h
		COMMENT "Building secure cpp sources from .proto files"
		DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/secure.proto
		COMMAND ${PROTOC_CMDLINE} --cpp_out=. ${CMAKE_CURRENT_SOURCE_DIR}/secure.proto
		WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/promex.pb.cc
                          ${CMAKE_CURRENT_BINARY_DIR}/promex.pb.h
                          ${CMAKE_CURRENT_BINARY_DIR}/promex.grpc.pb.cc
	                  ${CMAKE_CURRENT_BINARY_DIR}/promex.grpc.pb.h
	COMMENT "Building promex cpp sources from .proto files"
	DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/promex.proto ${CMAKE_CURRENT_SOURCE_DIR}/draios.proto
	COMMAND ${PROTOC_CMDLINE}
	        --cpp_out=.
		${CMAKE_CURRENT_SOURCE_DIR}/promex.proto
	COMMAND ${PROTOC_CMDLINE}
                --grpc_out=. --plugin=protoc-gen-grpc=${DRAIOS_DEPENDENCIES_DIR}/grpc-${DRAIOS_GRPC_VERSION}/bins/opt/grpc_cpp_plugin
		${CMAKE_CURRENT_SOURCE_DIR}/promex.proto
	WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
endif()

