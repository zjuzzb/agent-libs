include_directories(${DRAIOS_DEPENDENCIES_DIR}/grpc-${DRAIOS_GRPC_VERSION}/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/protobuf-${DRAIOS_PROTOBUF_VERSION}/target/include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../libsanalyzer/src) # for tdigest
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../userspace-shared/src) # for type_config
include_directories(${DRAIOS_DEPENDENCIES_DIR}/poco-${DRAIOS_POCO_VERSION}/target/include
)# for poco for type_config
include_directories(${DRAIOS_DEPENDENCIES_DIR}/yaml-${DRAIOS_YAML_VERSION}/target/include
)# for yaml for type_config
include_directories(${DRAIOS_DEPENDENCIES_DIR}/boost_${DRAIOS_BOOST_VERSION}) # for boost for
# type_config

include_directories(${CMAKE_CURRENT_BINARY_DIR}) # generated files
include_directories(${CMAKE_CURRENT_SOURCE_DIR}) # generated files refer to shipped ones

add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/aggregation_context.proto
           ${CMAKE_CURRENT_BINARY_DIR}/common.proto
           ${CMAKE_CURRENT_BINARY_DIR}/draios.proto
           ${CMAKE_CURRENT_BINARY_DIR}/handshake.proto
           ${CMAKE_CURRENT_BINARY_DIR}/agentino.proto
           ${CMAKE_CURRENT_BINARY_DIR}/metadata.proto
           ${CMAKE_CURRENT_BINARY_DIR}/profiling.proto
           ${CMAKE_CURRENT_BINARY_DIR}/secure.proto
    COMMENT "Fetching proto files from proto repo"
    DEPENDS ${PROJECT_SOURCE_DIR}/../protorepo/agent-be/proto/aggregation_context.proto
            ${PROJECT_SOURCE_DIR}/../protorepo/agent-be/proto/common.proto
            ${PROJECT_SOURCE_DIR}/../protorepo/agent-be/proto/draios.proto
            ${PROJECT_SOURCE_DIR}/../protorepo/agent-be/proto/handshake.proto
            ${PROJECT_SOURCE_DIR}/../protorepo/agent-be/proto/agentino.proto
            ${PROJECT_SOURCE_DIR}/../protorepo/agent-be/proto/metadata.proto
            ${PROJECT_SOURCE_DIR}/../protorepo/agent-be/proto/profiling.proto
            ${PROJECT_SOURCE_DIR}/../protorepo/agent-be/proto/secure.proto
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    COMMAND ${PROJECT_SOURCE_DIR}/../protorepo/agent-be/cpp/preproc.sh ${CMAKE_CURRENT_BINARY_DIR}
)

if(NOT CYGWIN)
    add_library(
        draiosproto STATIC
        aggregator_overrides.cpp
        aggregator_limits.cpp
        ${CMAKE_CURRENT_BINARY_DIR}/draios.pb.cc
        ${CMAKE_CURRENT_BINARY_DIR}/common.pb.cc
        ${CMAKE_CURRENT_BINARY_DIR}/aggregation_context.pb.cc
        ${CMAKE_CURRENT_BINARY_DIR}/handshake.pb.cc
        ${CMAKE_CURRENT_BINARY_DIR}/agentino.pb.cc
        ${CMAKE_CURRENT_BINARY_DIR}/tap.pb.cc
        ${CMAKE_CURRENT_BINARY_DIR}/secure.pb.cc
        ${CMAKE_CURRENT_BINARY_DIR}/profiling.pb.cc
        ${CMAKE_CURRENT_BINARY_DIR}/sdc_internal.pb.cc
        ${CMAKE_CURRENT_BINARY_DIR}/sdc_internal.grpc.pb.cc
        ${CMAKE_CURRENT_BINARY_DIR}/agent-prom.pb.cc
        ${CMAKE_CURRENT_BINARY_DIR}/agent-prom.grpc.pb.cc
        ${CMAKE_CURRENT_BINARY_DIR}/promex.pb.cc
        ${CMAKE_CURRENT_BINARY_DIR}/promex.grpc.pb.cc
        ${CMAKE_CURRENT_BINARY_DIR}/draios.proto_builder.cpp
    )
else()
    add_library(
        draiosproto STATIC
        ${CMAKE_CURRENT_BINARY_DIR}/draios.pb.cc
        ${CMAKE_CURRENT_BINARY_DIR}/common.pb.cc
        ${CMAKE_CURRENT_BINARY_DIR}/aggregation_context.pb.cc
        ${CMAKE_CURRENT_BINARY_DIR}/handshake.pb.cc
        ${CMAKE_CURRENT_BINARY_DIR}/agentino.pb.cc
        ${CMAKE_CURRENT_BINARY_DIR}/sdc_internal.pb.cc
        ${CMAKE_CURRENT_BINARY_DIR}/sdc_internal.grpc.pb.cc
        ${CMAKE_CURRENT_BINARY_DIR}/agent-prom.pb.cc
        ${CMAKE_CURRENT_BINARY_DIR}/agent-prom.grpc.pb.cc
        ${CMAKE_CURRENT_BINARY_DIR}/draios.proto_builder.cpp
    )
endif()
if(NOT CYGWIN)
    target_link_libraries(
        draiosproto
        ${DRAIOS_DEPENDENCIES_DIR}/grpc-${DRAIOS_GRPC_VERSION}/libs/opt/libgrpc++_unsecure.a
        ${DRAIOS_DEPENDENCIES_DIR}/grpc-${DRAIOS_GRPC_VERSION}/libs/opt/libgrpc_unsecure.a
        ${DRAIOS_DEPENDENCIES_DIR}/c-ares-${DRAIOS_CARES_VERSION}/target/lib/libcares.a
        ${DRAIOS_DEPENDENCIES_DIR}/protobuf-${DRAIOS_PROTOBUF_VERSION}/target/lib/libprotobuf.a
        ${DRAIOS_DEPENDENCIES_DIR}/zlib-${DRAIOS_ZLIB_VERSION}/libz.a
        pthread
    )
else()
    target_link_libraries(
        draiosproto
        ${DRAIOS_DEPENDENCIES_DIR}/protobuf-${DRAIOS_PROTOBUF_VERSION}/target/lib/libprotobuf.a
    )
endif()

set(PROTOC_CMDLINE
    LD_LIBRARY_PATH=${DRAIOS_DEPENDENCIES_DIR}/protobuf-${DRAIOS_PROTOBUF_VERSION}/target/lib
    ${DRAIOS_DEPENDENCIES_DIR}/protobuf-${DRAIOS_PROTOBUF_VERSION}/target/bin/protoc
)

function(generate_proto proto)
    # Argument handling here is slightly subtle: you can pass multiple .proto files and all will be
    # set as the target dependencies and for the include path. The first argument is treated a bit
    # specially since the output file names are based on the first input (the only one we pass to
    # protoc explicitly; the other ones are assumed to be imported in the first .proto)
    #
    # The ARGV list contains all arguments, including the named ones. The extra (unnamed) arguments
    # live in a list called ARGN, so technically we should use "${proto};${ARGN}" here (modulo cmake
    # syntax for list concatenation).
    #
    # If you ever add an argument after `proto` that's not a path to a .proto file, you need to
    # revisit the two lines below.
    set(DEPENDS ${ARGV})
    foreach(PROTO ${ARGV})
        get_filename_component(PROTO_DIR ${PROTO} DIRECTORY)
        list(APPEND PROTOC_OPTIONS -I ${PROTO_DIR})
    endforeach()

    get_filename_component(PROTO_NAME ${proto} NAME_WE)
    add_custom_command(
        OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/${PROTO_NAME}.pb.cc
               ${CMAKE_CURRENT_BINARY_DIR}/${PROTO_NAME}.pb.h
        COMMENT "Building ${PROTO_NAME} cpp sources from ${proto}"
        DEPENDS ${DEPENDS}
        COMMAND ${PROTOC_CMDLINE} ${PROTOC_OPTIONS} --cpp_out=. ${proto}
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    )
endfunction()

function(generate_grpc proto)
    # See comment in `generate_proto` above
    set(DEPENDS ${ARGV})
    foreach(PROTO ${ARGV})
        get_filename_component(PROTO_DIR ${PROTO} DIRECTORY)
        list(APPEND PROTOC_OPTIONS -I ${PROTO_DIR})
    endforeach()

    get_filename_component(PROTO_NAME ${proto} NAME_WE)
    add_custom_command(
        OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/${PROTO_NAME}.grpc.pb.cc
               ${CMAKE_CURRENT_BINARY_DIR}/${PROTO_NAME}.grpc.pb.h
        COMMENT "Building ${PROTO_NAME} cpp sources from ${proto}"
        DEPENDS ${DEPENDS}
        COMMAND
            ${PROTOC_CMDLINE} ${PROTOC_OPTIONS} --grpc_out=.
            --plugin=protoc-gen-grpc=${DRAIOS_DEPENDENCIES_DIR}/grpc-${DRAIOS_GRPC_VERSION}/bins/opt/grpc_cpp_plugin
            ${proto}
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    )
endfunction()

generate_proto(${CMAKE_CURRENT_BINARY_DIR}/aggregation_context.proto)
generate_proto(${CMAKE_CURRENT_BINARY_DIR}/common.proto)
generate_proto(${CMAKE_CURRENT_BINARY_DIR}/agentino.proto ${CMAKE_CURRENT_BINARY_DIR}/draios.proto)
generate_proto(${CMAKE_CURRENT_BINARY_DIR}/draios.proto ${CMAKE_CURRENT_BINARY_DIR}/common.proto)
generate_proto(
    ${CMAKE_CURRENT_BINARY_DIR}/handshake.proto
    ${CMAKE_CURRENT_BINARY_DIR}/aggregation_context.proto ${CMAKE_CURRENT_BINARY_DIR}/common.proto
)
generate_proto(
    ${CMAKE_CURRENT_BINARY_DIR}/metadata.proto ${CMAKE_CURRENT_BINARY_DIR}/draios.proto
    ${CMAKE_CURRENT_BINARY_DIR}/common.proto
)
generate_proto(${CMAKE_CURRENT_BINARY_DIR}/profiling.proto)
generate_proto(${CMAKE_CURRENT_BINARY_DIR}/secure.proto)

generate_proto(
    ${CMAKE_CURRENT_SOURCE_DIR}/promex.proto ${CMAKE_CURRENT_BINARY_DIR}/draios.proto
    ${CMAKE_CURRENT_BINARY_DIR}/common.proto
)
generate_proto(
    ${CMAKE_CURRENT_SOURCE_DIR}/sdc_internal.proto ${CMAKE_CURRENT_BINARY_DIR}/draios.proto
    ${CMAKE_CURRENT_BINARY_DIR}/common.proto
)
generate_proto(${CMAKE_CURRENT_SOURCE_DIR}/tap.proto)
generate_proto(${PROJECT_SOURCE_DIR}/../protorepo/agent/agent-prom.proto)

if(NOT CYGWIN)
    generate_grpc(${PROJECT_SOURCE_DIR}/../protorepo/agent/agent-prom.proto)
    generate_grpc(
        ${CMAKE_CURRENT_SOURCE_DIR}/sdc_internal.proto ${CMAKE_CURRENT_BINARY_DIR}/draios.proto
        ${CMAKE_CURRENT_BINARY_DIR}/common.proto
    )
    generate_grpc(
        ${CMAKE_CURRENT_SOURCE_DIR}/promex.proto ${CMAKE_CURRENT_BINARY_DIR}/draios.proto
        ${CMAKE_CURRENT_BINARY_DIR}/common.proto
    )
endif()

install(
    DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/aggr_pbs
    DESTINATION ${CMAKE_INSTALL_PREFIX}/test
    COMPONENT tests
)

# Alpine builder has python3. Legacy Centos builder only has python 2.6, so we need to jank to get
# python 2.7 so protoc can run properly
if(NOT ALPINE_BUILDER)
    add_custom_command(
        OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/draios.proto_builder.cpp
               ${CMAKE_CURRENT_BINARY_DIR}/draios.proto_builder.h
               ${CMAKE_CURRENT_BINARY_DIR}/draios.proto.h
        COMMENT "Building aggregator sources from .proto files"
        DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/draios.proto
        DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/common.proto
        DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/aggregation_context.proto
        DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/handshake.proto
        DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/agentino.proto
        DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/draios-aggregator-plugin.py
        DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/draios_proto_extension.py
        DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/protoc_plugin.sh
        COMMAND cp ${CMAKE_CURRENT_SOURCE_DIR}/draios_proto_extension.py ${CMAKE_CURRENT_BINARY_DIR}
        COMMAND
            scl enable python27
            "${CMAKE_CURRENT_SOURCE_DIR}/protoc_plugin.sh ${DRAIOS_DEPENDENCIES_DIR}/protobuf-${DRAIOS_PROTOBUF_VERSION}/target/bin/ ${PROJECT_BINARY_DIR}/userspace/draiosproto ${CMAKE_CURRENT_SOURCE_DIR}/draios-aggregator-plugin.py ${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_CURRENT_BINARY_DIR}/draios.proto"
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    )
else()
    add_custom_command(
        OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/draios.proto_builder.cpp
               ${CMAKE_CURRENT_BINARY_DIR}/draios.proto_builder.h
               ${CMAKE_CURRENT_BINARY_DIR}/draios.proto.h
        COMMENT "Building aggregator sources from .proto files"
        DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/draios.proto
        DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/common.proto
        DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/aggregation_context.proto
        DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/handshake.proto
        DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/agentino.proto
        DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/draios-aggregator-plugin.py
        DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/draios_proto_extension.py
        DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/protoc_plugin.sh
        COMMAND cp ${CMAKE_CURRENT_SOURCE_DIR}/draios_proto_extension.py ${CMAKE_CURRENT_BINARY_DIR}
        COMMAND
            ${DRAIOS_DEPENDENCIES_DIR}/protobuf-${DRAIOS_PROTOBUF_VERSION}/target/bin/protoc -I
            ${PROJECT_BINARY_DIR}/userspace/draiosproto
            --plugin=protoc-gen-custom=${CMAKE_CURRENT_SOURCE_DIR}/draios-aggregator-plugin.py
            --custom_out=${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_CURRENT_BINARY_DIR}/draios.proto
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    )
endif()
