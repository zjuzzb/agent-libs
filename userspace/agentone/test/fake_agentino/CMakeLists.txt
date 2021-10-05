include_directories(${CMAKE_CURRENT_BINARY_DIR}/../../../draiosproto)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../../../dragent/src)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/protobuf-${DRAIOS_PROTOBUF_VERSION}/target/include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../../../userspace-shared/src)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../../../libsanalyzer/src)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/poco-${DRAIOS_POCO_VERSION}/target/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/yaml-${DRAIOS_YAML_VERSION}/target/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/boost_${DRAIOS_BOOST_VERSION})
include_directories(${DRAIOS_DEPENDENCIES_DIR}/grpc-${DRAIOS_GRPC_VERSION}/include)

set(THREADS_PREFER_PTHREAD_FLAG true)
find_package(Threads REQUIRED)

add_library(fake-agentino STATIC fake_agentino.cpp)
target_link_libraries(
    fake-agentino draiosproto dragentl
    ${DRAIOS_DEPENDENCIES_DIR}/zlib-${DRAIOS_ZLIB_VERSION}/libz.a
    ${DRAIOS_DEPENDENCIES_DIR}/poco-${DRAIOS_POCO_VERSION}/target/lib/libPocoFoundation.a
    ${DRAIOS_DEPENDENCIES_DIR}/openssl-${DRAIOS_OPENSSL_VERSION}/target/lib/libssl.a
    ${DRAIOS_DEPENDENCIES_DIR}/openssl-${DRAIOS_OPENSSL_VERSION}/target/lib/libcrypto.a
    ${CMAKE_THREAD_LIBS_INIT}
)
