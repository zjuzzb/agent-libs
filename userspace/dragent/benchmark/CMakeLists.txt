add_executable(benchmark-dragent protobuf.bm.cpp)

add_dependencies(benchmark-dragent dragentl draiosproto)
add_definitions(-DHAS_ANALYZER)

include_directories(${DRAIOS_DEPENDENCIES_DIR}/benchmark-${DRAIOS_BENCHMARK_VERSION}/include)

include_directories(${CMAKE_CURRENT_BINARY_DIR})
include_directories(${DRAIOS_DEPENDENCIES_DIR}/protobuf-${DRAIOS_PROTOBUF_VERSION}/target/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/zlib-${DRAIOS_ZLIB_VERSION})
include_directories(${LIBSCAP_INCLUDE_DIR})
include_directories(${LIBSINSP_INCLUDE_DIRS})
include_directories(${PROJECT_SOURCE_DIR}/../oss-falco/userspace/engine)
include_directories(${PROJECT_SOURCE_DIR}/userspace/libpromscrape/src)
include_directories(${PROJECT_SOURCE_DIR}/userspace/libsanalyzer/src)
include_directories(${PROJECT_SOURCE_DIR}/userspace/dragent/src)
include_directories(${PROJECT_SOURCE_DIR}/userspace/dragent/test_helpers)
include_directories(${PROJECT_SOURCE_DIR}/userspace/userspace-shared/src)
include_directories(${PROJECT_SOURCE_DIR}/userspace/userspace-shared/test-helpers)
include_directories(${PROJECT_SOURCE_DIR}/userspace/draiosproto)
include_directories(${PROJECT_BINARY_DIR}/userspace/draiosproto)
include_directories(${PROJECT_BINARY_DIR}/userspace/dragent/src)
include_directories(${PROJECT_BINARY_DIR}/userspace/engine)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/openssl-${DRAIOS_OPENSSL_VERSION}/target/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/poco-${DRAIOS_POCO_VERSION}/target/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/yaml-${DRAIOS_YAML_VERSION}/target/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/boost_${DRAIOS_BOOST_VERSION})
include_directories(${DRAIOS_DEPENDENCIES_DIR}/curl-${DRAIOS_CURL_VERSION}/include)
include_directories(
    ${DRAIOS_DEPENDENCIES_DIR}/gperftools-${DRAIOS_GPERFTOOLS_VERSION}/target/include
)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/libb64-${DRAIOS_B64_VERSION}/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/jq-${DRAIOS_JQ_VERSION})
include_directories(${DRAIOS_DEPENDENCIES_DIR}/grpc-${DRAIOS_GRPC_VERSION}/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/tbb-${DRAIOS_TBB_VERSION}/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/gtest-${DRAIOS_GTEST_VERSION}/fused-src/gtest)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/gtest-${DRAIOS_GTEST_VERSION}/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/c-ares-${DRAIOS_CARES_VERSION}/target/include)

target_link_libraries(
    benchmark-dragent
    ${DRAIOS_DEPENDENCIES_DIR}/benchmark-${DRAIOS_BENCHMARK_VERSION}/build/src/libbenchmark.a
    ${DRAIOS_DEPENDENCIES_DIR}/benchmark-${DRAIOS_BENCHMARK_VERSION}/build/src/libbenchmark_main.a
    rt
    dragentl
    draiosproto
)

add_custom_target(run-benchmark-dragent COMMAND benchmark-dragent)

install(
    TARGETS benchmark-dragent
    DESTINATION ${CMAKE_INSTALL_PREFIX}/test/
    COMPONENT tests
)

add_executable(benchmark-securitymgr security_mgr.bm.cpp)

target_link_libraries(
    benchmark-securitymgr
    pthread
    sanalyzer
    dragentl
    draiosproto
    falco_engine
    test-helpers-dragent
    ${DRAIOS_DEPENDENCIES_DIR}/poco-${DRAIOS_POCO_VERSION}/target/lib/libPocoNet.a
    ${DRAIOS_DEPENDENCIES_DIR}/poco-${DRAIOS_POCO_VERSION}/target/lib/libPocoNetSSL.a
    ${DRAIOS_DEPENDENCIES_DIR}/poco-${DRAIOS_POCO_VERSION}/target/lib/libPocoFoundation.a
    ${DRAIOS_DEPENDENCIES_DIR}/zlib-${DRAIOS_ZLIB_VERSION}/libz.a
    ${DRAIOS_DEPENDENCIES_DIR}/yaml-${DRAIOS_YAML_VERSION}/target/lib/libyaml-cpp.a
    ${DRAIOS_DEPENDENCIES_DIR}/jq-${DRAIOS_JQ_VERSION}/.libs/libjq.a
    ${DRAIOS_DEPENDENCIES_DIR}/openssl-${DRAIOS_OPENSSL_VERSION}/target/lib/libssl.a
    ${DRAIOS_DEPENDENCIES_DIR}/openssl-${DRAIOS_OPENSSL_VERSION}/target/lib/libcrypto.a
    ${DRAIOS_DEPENDENCIES_DIR}/benchmark-${DRAIOS_BENCHMARK_VERSION}/build/src/libbenchmark.a
    ${DRAIOS_DEPENDENCIES_DIR}/benchmark-${DRAIOS_BENCHMARK_VERSION}/build/src/libbenchmark_main.a
    ${DRAIOS_DEPENDENCIES_DIR}/gperftools-${DRAIOS_GPERFTOOLS_VERSION}/target/lib/libtcmalloc_and_profiler.a
)

target_compile_definitions(benchmark-securitymgr PUBLIC SYSDIG_TEST)

install(
    TARGETS benchmark-securitymgr
    DESTINATION ${CMAKE_INSTALL_PREFIX}/test/
    COMPONENT tests
)
