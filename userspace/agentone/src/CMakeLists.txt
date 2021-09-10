include_directories(${CMAKE_CURRENT_BINARY_DIR}/../../draiosproto)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../../dragent/src)
include_directories(${CMAKE_CURRENT_BINARY_DIR}/../../dragent/src)
include_directories(${PROJECT_SOURCE_DIR}/userspace/draiosproto)
include_directories(${PROJECT_SOURCE_DIR}/../oss-falco/userspace/engine)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/gtest-${DRAIOS_GTEST_VERSION}/include)
include_directories(${PROJECT_SOURCE_DIR}/userspace/librest/src)

include_directories(${DRAIOS_DEPENDENCIES_DIR}/protobuf-${DRAIOS_PROTOBUF_VERSION}/target/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/c-ares-${DRAIOS_CARES_VERSION}/target/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/libb64-${DRAIOS_B64_VERSION}/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/jq-${DRAIOS_JQ_VERSION})
include_directories(
    ${DRAIOS_DEPENDENCIES_DIR}/gperftools-${DRAIOS_GPERFTOOLS_VERSION}/target/include
)

# The following includes are necessary because connection_manager pulls in the world just to get the
# message_handler definition
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../../userspace-shared/src)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../../libpromscrape/src)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../../libsanalyzer/src)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/poco-${DRAIOS_POCO_VERSION}/target/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/yaml-${DRAIOS_YAML_VERSION}/target/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/boost_${DRAIOS_BOOST_VERSION})
include_directories(${DRAIOS_DEPENDENCIES_DIR}/grpc-${DRAIOS_GRPC_VERSION}/include)

add_definitions(-DHAS_ANALYZER)

add_library(
    agentonel STATIC agentino_connection.cpp agentino_manager.cpp container_manager.cpp
                     thread_pool.cpp $<TARGET_OBJECTS:appcommonl>
)
target_link_libraries(agentonel draiosproto)

add_executable(agentone agentone_main.cpp agentone.cpp)
target_link_libraries(
    agentone
    pthread
    sanalyzer
    agentonel
    draiosproto
    librestl
    falco_engine
    ${DRAIOS_DEPENDENCIES_DIR}/libb64-${DRAIOS_B64_VERSION}/src/libb64.a
    ${DRAIOS_DEPENDENCIES_DIR}/poco-${DRAIOS_POCO_VERSION}/target/lib/libPocoNetSSL.a
    ${DRAIOS_DEPENDENCIES_DIR}/poco-${DRAIOS_POCO_VERSION}/target/lib/libPocoUtil.a
    ${DRAIOS_DEPENDENCIES_DIR}/poco-${DRAIOS_POCO_VERSION}/target/lib/libPocoNet.a
    ${DRAIOS_DEPENDENCIES_DIR}/poco-${DRAIOS_POCO_VERSION}/target/lib/libPocoFoundation.a
    rt
    ${DRAIOS_DEPENDENCIES_DIR}/yaml-${DRAIOS_YAML_VERSION}/target/lib/libyaml-cpp.a
    ${DRAIOS_DEPENDENCIES_DIR}/openssl-${DRAIOS_OPENSSL_VERSION}/target/lib/libssl.a
    ${DRAIOS_DEPENDENCIES_DIR}/openssl-${DRAIOS_OPENSSL_VERSION}/target/lib/libcrypto.a
    ${DRAIOS_DEPENDENCIES_DIR}/gperftools-${DRAIOS_GPERFTOOLS_VERSION}/target/lib/libtcmalloc_and_profiler.a
)

install(
    TARGETS agentone
    DESTINATION ${CMAKE_INSTALL_PREFIX}/bin
    COMPONENT agentone
)
