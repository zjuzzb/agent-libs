include_directories(${DRAIOS_DEPENDENCIES_DIR}/grpc-${DRAIOS_GRPC_VERSION}/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/protobuf-${DRAIOS_PROTOBUF_VERSION}/target/include)
include_directories(${PROJECT_SOURCE_DIR}/userspace/draiosproto)
include_directories(${PROJECT_BINARY_DIR}/userspace/draiosproto)

add_executable(grpc_test_server grpc_test_server.cpp)

add_dependencies(grpc_test_server draiosproto)

target_link_libraries(
    grpc_test_server
    draiosproto
    ${DRAIOS_DEPENDENCIES_DIR}/grpc-${DRAIOS_GRPC_VERSION}/libs/opt/libgrpc++_unsecure.a
    ${DRAIOS_DEPENDENCIES_DIR}/grpc-${DRAIOS_GRPC_VERSION}/libs/opt/libgrpc_unsecure.a
    ${DRAIOS_DEPENDENCIES_DIR}/c-ares-${DRAIOS_CARES_VERSION}/target/lib/libcares.a
    ${DRAIOS_DEPENDENCIES_DIR}/protobuf-${DRAIOS_PROTOBUF_VERSION}/target/lib/libprotobuf.a
    pthread
    rt
)

install(
    TARGETS grpc_test_server
    DESTINATION ${CMAKE_INSTALL_PREFIX}/test/resources
    COMPONENT tests
)
