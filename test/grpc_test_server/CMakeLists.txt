include_directories(${DRAIOS_DEPENDENCIES_DIR}/grpc-${DRAIOS_GRPC_VERSION}/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/protobuf-${DRAIOS_PROTOBUF_VERSION}/target/include)
include_directories(${CMAKE_CURRENT_BINARY_DIR})

set(PROTOC LD_LIBRARY_PATH=${DRAIOS_DEPENDENCIES_DIR}/protobuf-${DRAIOS_PROTOBUF_VERSION}/target/lib
        ${DRAIOS_DEPENDENCIES_DIR}/protobuf-${DRAIOS_PROTOBUF_VERSION}/target/bin/protoc)

add_custom_command(OUTPUT
        ${CMAKE_CURRENT_BINARY_DIR}/sdc_internal.grpc.pb.cc
        ${CMAKE_CURRENT_BINARY_DIR}/sdc_internal.grpc.pb.h
        ${CMAKE_CURRENT_BINARY_DIR}/sdc_internal.pb.cc
        ${CMAKE_CURRENT_BINARY_DIR}/sdc_internal.pb.h
        ${CMAKE_CURRENT_BINARY_DIR}/draios.grpc.pb.cc
        ${CMAKE_CURRENT_BINARY_DIR}/draios.grpc.pb.h
        ${CMAKE_CURRENT_BINARY_DIR}/draios.pb.cc
        ${CMAKE_CURRENT_BINARY_DIR}/draios.pb.h
        COMMENT "Generate sdc_internal grpc code"
        DEPENDS ${PROJECT_SOURCE_DIR}/userspace/draiosproto/sdc_internal.proto
        DEPENDS ${PROJECT_SOURCE_DIR}/userspace/draiosproto/draios.proto
        COMMAND ${PROTOC} -I ${PROJECT_SOURCE_DIR}/userspace/draiosproto --cpp_out=. ${PROJECT_SOURCE_DIR}/userspace/draiosproto/sdc_internal.proto
        COMMAND ${PROTOC} -I ${PROJECT_SOURCE_DIR}/userspace/draiosproto --cpp_out=. ${PROJECT_SOURCE_DIR}/userspace/draiosproto/draios.proto
        COMMAND ${PROTOC} -I ${PROJECT_SOURCE_DIR}/userspace/draiosproto --grpc_out=. --plugin=protoc-gen-grpc=${DRAIOS_DEPENDENCIES_DIR}/grpc-1.8.1/bins/opt/grpc_cpp_plugin ${PROJECT_SOURCE_DIR}/userspace/draiosproto/sdc_internal.proto
        COMMAND ${PROTOC} -I ${PROJECT_SOURCE_DIR}/userspace/draiosproto --grpc_out=. --plugin=protoc-gen-grpc=${DRAIOS_DEPENDENCIES_DIR}/grpc-1.8.1/bins/opt/grpc_cpp_plugin ${PROJECT_SOURCE_DIR}/userspace/draiosproto/draios.proto
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

add_executable(grpc_test_server
        grpc_test_server.cpp
        ${CMAKE_CURRENT_BINARY_DIR}/sdc_internal.grpc.pb.cc
        ${CMAKE_CURRENT_BINARY_DIR}/sdc_internal.pb.cc
        ${CMAKE_CURRENT_BINARY_DIR}/draios.grpc.pb.cc
        ${CMAKE_CURRENT_BINARY_DIR}/draios.pb.cc
        )

target_link_libraries(grpc_test_server
        ${DRAIOS_DEPENDENCIES_DIR}/grpc-1.8.1/libs/opt/libgrpc++_unsecure.a
        ${DRAIOS_DEPENDENCIES_DIR}/grpc-1.8.1/libs/opt/libgrpc_unsecure.a
        ${DRAIOS_DEPENDENCIES_DIR}/c-ares-${DRAIOS_CARES_VERSION}/target/lib/libcares.a
        ${DRAIOS_DEPENDENCIES_DIR}/protobuf-${DRAIOS_PROTOBUF_VERSION}/target/lib/libprotobuf.a
        pthread
        rt)

install(TARGETS grpc_test_server
        DESTINATION ${CMAKE_INSTALL_PREFIX}/test/resources
        COMPONENT tests)
