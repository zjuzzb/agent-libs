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

# These copies are very very jank. Originally we used the file(copy construct, but cmake doesn't
# necessarily wait for the copy to complete before trying to build dependencies based off it, so it
# often lead to invalid downstream results that required a clean we cannot have individual copy
# commands for each of them, as cmake does not see the dependency on the .h files, so we have to
# encode them here. In short, CMAKE is a disaster, so we have to do ugly things like this.
add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/aggregator_overrides.cpp
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/aggregator_overrides.h
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/aggregator_limits.h
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/aggregator_limits.cpp
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/aggregator_base.h
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/aggregator_overrides.cpp
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/aggregator_overrides.h
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/aggregator_limits.h
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/aggregator_limits.cpp
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/aggregator_base.h
    COMMENT "Copying aggregator_overrides sources to binary dir."
    COMMAND cp ${CMAKE_CURRENT_SOURCE_DIR}/aggregator_overrides.cpp ${CMAKE_CURRENT_BINARY_DIR}
    COMMAND cp ${CMAKE_CURRENT_SOURCE_DIR}/aggregator_overrides.h ${CMAKE_CURRENT_BINARY_DIR}
    COMMAND cp ${CMAKE_CURRENT_SOURCE_DIR}/aggregator_limits.h ${CMAKE_CURRENT_BINARY_DIR}
    COMMAND cp ${CMAKE_CURRENT_SOURCE_DIR}/aggregator_limits.cpp ${CMAKE_CURRENT_BINARY_DIR}
    COMMAND cp ${CMAKE_CURRENT_SOURCE_DIR}/aggregator_base.h ${CMAKE_CURRENT_BINARY_DIR}
)

function(copy_proto_source target)

    add_custom_command(
        OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/${target}
        DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/${target}
        COMMENT "Copying ${target} to binary dir."
        COMMAND cp ${CMAKE_CURRENT_SOURCE_DIR}/${target} ${CMAKE_CURRENT_BINARY_DIR}
    )

endfunction()

copy_proto_source(draios_proto_extension.py)
copy_proto_source(profiling.proto)
copy_proto_source(promex.proto)
copy_proto_source(sdc_internal.proto)
copy_proto_source(secure.proto)
copy_proto_source(tap.proto)

add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/common.proto ${CMAKE_CURRENT_BINARY_DIR}/draios.proto
           ${CMAKE_CURRENT_BINARY_DIR}/handshake.proto
           ${CMAKE_CURRENT_BINARY_DIR}/aggregation_context.proto
    COMMENT "Fetching proto files from proto repo"
    DEPENDS ${PROJECT_SOURCE_DIR}/../protorepo/agent-be/proto/draios.proto
    DEPENDS ${PROJECT_SOURCE_DIR}/../protorepo/agent-be/proto/common.proto
    DEPENDS ${PROJECT_SOURCE_DIR}/../protorepo/agent-be/proto/handshake.proto
    DEPENDS ${PROJECT_SOURCE_DIR}/../protorepo/agent-be/proto/aggregation_context.proto
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    COMMAND ${PROJECT_SOURCE_DIR}/../protorepo/agent-be/cpp/preproc.sh ${CMAKE_CURRENT_BINARY_DIR}
)

if(NOT CYGWIN)
    add_library(
        draiosproto STATIC
        ${CMAKE_CURRENT_BINARY_DIR}/aggregator_overrides.cpp
        ${CMAKE_CURRENT_BINARY_DIR}/aggregator_limits.cpp
        ${CMAKE_CURRENT_BINARY_DIR}/draios.pb.cc
        ${CMAKE_CURRENT_BINARY_DIR}/common.pb.cc
        ${CMAKE_CURRENT_BINARY_DIR}/aggregation_context.pb.cc
        ${CMAKE_CURRENT_BINARY_DIR}/handshake.pb.cc
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
    ${DRAIOS_DEPENDENCIES_DIR}/protobuf-${DRAIOS_PROTOBUF_VERSION}/target/bin/protoc -I
    ${PROJECT_BINARY_DIR}/userspace/draiosproto
)

if(NOT CYGWIN)
    add_custom_command(
        OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/agent-prom.pb.cc
               ${CMAKE_CURRENT_BINARY_DIR}/agent-prom.pb.h
               ${CMAKE_CURRENT_BINARY_DIR}/agent-prom.grpc.pb.cc
               ${CMAKE_CURRENT_BINARY_DIR}/agent-prom.grpc.pb.h
        COMMENT "Building agent-prom cpp sources from .proto files"
        DEPENDS ${PROJECT_SOURCE_DIR}/../protorepo/agent/agent-prom.proto
        COMMAND ${PROTOC_CMDLINE} -I ${PROJECT_SOURCE_DIR}/../protorepo/agent --cpp_out=.
                ${PROJECT_SOURCE_DIR}/../protorepo/agent/agent-prom.proto
        COMMAND
            ${PROTOC_CMDLINE} -I ${PROJECT_SOURCE_DIR}/../protorepo/agent --grpc_out=.
            --plugin=protoc-gen-grpc=${DRAIOS_DEPENDENCIES_DIR}/grpc-${DRAIOS_GRPC_VERSION}/bins/opt/grpc_cpp_plugin
            ${PROJECT_SOURCE_DIR}/../protorepo/agent/agent-prom.proto
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    )

    add_custom_command(
        OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/sdc_internal.pb.cc
               ${CMAKE_CURRENT_BINARY_DIR}/sdc_internal.pb.h
               ${CMAKE_CURRENT_BINARY_DIR}/sdc_internal.grpc.pb.cc
               ${CMAKE_CURRENT_BINARY_DIR}/sdc_internal.grpc.pb.h
        COMMENT "Building sdc_internal cpp sources from .proto files"
        DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/sdc_internal.proto
                ${CMAKE_CURRENT_BINARY_DIR}/draios.proto
        DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/sdc_internal.proto
                ${CMAKE_CURRENT_BINARY_DIR}/sdc_internal.proto
        COMMAND ${PROTOC_CMDLINE} --cpp_out=. ${CMAKE_CURRENT_BINARY_DIR}/sdc_internal.proto
        COMMAND
            ${PROTOC_CMDLINE} --grpc_out=.
            --plugin=protoc-gen-grpc=${DRAIOS_DEPENDENCIES_DIR}/grpc-${DRAIOS_GRPC_VERSION}/bins/opt/grpc_cpp_plugin
            ${CMAKE_CURRENT_BINARY_DIR}/sdc_internal.proto
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    )
endif()

if(NOT CYGWIN)
    add_custom_command(
        OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/draios.pb.cc
               ${CMAKE_CURRENT_BINARY_DIR}/draios.pb.h
               ${CMAKE_CURRENT_BINARY_DIR}/common.pb.h
               ${CMAKE_CURRENT_BINARY_DIR}/common.pb.cc
               ${CMAKE_CURRENT_BINARY_DIR}/aggregation_context.pb.h
               ${CMAKE_CURRENT_BINARY_DIR}/aggregation_context.pb.cc
               ${CMAKE_CURRENT_BINARY_DIR}/handshake.pb.h
               ${CMAKE_CURRENT_BINARY_DIR}/handshake.pb.cc
        COMMENT "Building draiosproto cpp sources from .proto files"
        DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/draios.proto
        DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/sdc_internal.proto
        DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/common.proto
        DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/aggregation_context.proto
        DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/handshake.proto
        COMMAND
            ${PROTOC_CMDLINE} --grpc_out=.
            --plugin=protoc-gen-grpc=${DRAIOS_DEPENDENCIES_DIR}/grpc-${DRAIOS_GRPC_VERSION}/bins/opt/grpc_cpp_plugin
            ${CMAKE_CURRENT_BINARY_DIR}/sdc_internal.proto
        COMMAND ${PROTOC_CMDLINE} --cpp_out=. ${CMAKE_CURRENT_BINARY_DIR}/draios.proto
        COMMAND ${PROTOC_CMDLINE} --cpp_out=. ${CMAKE_CURRENT_BINARY_DIR}/common.proto
        COMMAND ${PROTOC_CMDLINE} --cpp_out=. ${CMAKE_CURRENT_BINARY_DIR}/aggregation_context.proto
        COMMAND ${PROTOC_CMDLINE} --cpp_out=. ${CMAKE_CURRENT_BINARY_DIR}/handshake.proto
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    )
else()
    add_custom_command(
        OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/draios.pb.cc
               ${CMAKE_CURRENT_BINARY_DIR}/draios.pb.h
               ${CMAKE_CURRENT_BINARY_DIR}/common.pb.h
               ${CMAKE_CURRENT_BINARY_DIR}/common.pb.cc
               ${CMAKE_CURRENT_BINARY_DIR}/aggregation_context.pb.h
               ${CMAKE_CURRENT_BINARY_DIR}/aggregation_context.pb.cc
               ${CMAKE_CURRENT_BINARY_DIR}/handshake.pb.h
               ${CMAKE_CURRENT_BINARY_DIR}/handshake.pb.cc
        COMMENT "Building draiosproto cpp sources from .proto files"
        DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/draios.proto
        DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/common.proto
        DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/aggregation_context.proto
        DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/handshake.proto
        COMMAND ${PROTOC_CMDLINE} --cpp_out=. ${CMAKE_CURRENT_BINARY_DIR}/draios.proto
        COMMAND ${PROTOC_CMDLINE} --cpp_out=. ${CMAKE_CURRENT_BINARY_DIR}/common.proto
        COMMAND ${PROTOC_CMDLINE} --cpp_out=. ${CMAKE_CURRENT_BINARY_DIR}/aggregation_context.proto
        COMMAND ${PROTOC_CMDLINE} --cpp_out=. ${CMAKE_CURRENT_BINARY_DIR}/handshake.proto
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    )
endif()

install(
    DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/aggr_pbs
    DESTINATION ${CMAKE_INSTALL_PREFIX}/test
    COMPONENT tests
)
add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/draios.proto_builder.cpp
           ${CMAKE_CURRENT_BINARY_DIR}/draios.proto_builder.h
           ${CMAKE_CURRENT_BINARY_DIR}/draios.proto.h
    COMMENT "Building aggregator sources from .proto files"
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/draios.proto
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/common.proto
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/aggregation_context.proto
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/handshake.proto
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/draios-aggregator-plugin.py
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/draios_proto_extension.py
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/protoc_plugin.sh
    COMMAND
        scl enable python27
        "${CMAKE_CURRENT_SOURCE_DIR}/protoc_plugin.sh ${DRAIOS_DEPENDENCIES_DIR}/protobuf-${DRAIOS_PROTOBUF_VERSION}/target/bin/ ${PROJECT_BINARY_DIR}/userspace/draiosproto ${CMAKE_CURRENT_SOURCE_DIR}/draios-aggregator-plugin.py ${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_CURRENT_BINARY_DIR}/draios.proto"
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)

if(NOT CYGWIN)
    add_custom_command(
        OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/tap.pb.cc ${CMAKE_CURRENT_BINARY_DIR}/tap.pb.h
        COMMENT "Building tap cpp sources from .proto files"
        DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/tap.proto
        COMMAND ${PROTOC_CMDLINE} --cpp_out=. ${CMAKE_CURRENT_BINARY_DIR}/tap.proto
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    )

    add_custom_command(
        OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/secure.pb.cc ${CMAKE_CURRENT_BINARY_DIR}/secure.pb.h
        COMMENT "Building secure cpp sources from .proto files"
        DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/secure.proto
        COMMAND ${PROTOC_CMDLINE} --cpp_out=. ${CMAKE_CURRENT_BINARY_DIR}/secure.proto
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    )

    add_custom_command(
        OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/profiling.pb.cc
               ${CMAKE_CURRENT_BINARY_DIR}/profiling.pb.h
        COMMENT "Building profiling cpp sources from .proto files"
        DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/profiling.proto
        COMMAND ${PROTOC_CMDLINE} --cpp_out=. ${CMAKE_CURRENT_BINARY_DIR}/profiling.proto
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    )

    add_custom_command(
        OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/promex.pb.cc ${CMAKE_CURRENT_BINARY_DIR}/promex.pb.h
               ${CMAKE_CURRENT_BINARY_DIR}/promex.grpc.pb.cc
               ${CMAKE_CURRENT_BINARY_DIR}/promex.grpc.pb.h
        COMMENT "Building promex cpp sources from .proto files"
        DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/promex.proto ${CMAKE_CURRENT_BINARY_DIR}/draios.proto
        COMMAND ${PROTOC_CMDLINE} --cpp_out=. ${CMAKE_CURRENT_BINARY_DIR}/promex.proto
        COMMAND
            ${PROTOC_CMDLINE} --grpc_out=.
            --plugin=protoc-gen-grpc=${DRAIOS_DEPENDENCIES_DIR}/grpc-${DRAIOS_GRPC_VERSION}/bins/opt/grpc_cpp_plugin
            ${CMAKE_CURRENT_BINARY_DIR}/promex.proto
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    )
endif()
