add_executable(benchmark-dragent
        protobuf.bm.cpp)

add_dependencies(benchmark-dragent dragentl draiosproto)
add_definitions(-DHAS_ANALYZER)

include_directories(${DRAIOS_DEPENDENCIES_DIR}/benchmark/include)

include_directories(${CMAKE_CURRENT_BINARY_DIR})
include_directories(${DRAIOS_DEPENDENCIES_DIR}/protobuf-${DRAIOS_PROTOBUF_VERSION}/target/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/zlib-${DRAIOS_ZLIB_VERSION})
include_directories(${PROJECT_SOURCE_DIR}/../sysdig/userspace/async)
include_directories(${PROJECT_SOURCE_DIR}/../sysdig/userspace/libscap)
include_directories(${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp)
include_directories(${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/third-party/jsoncpp)
include_directories(${PROJECT_SOURCE_DIR}/../oss-falco/userspace/engine)
include_directories(${PROJECT_SOURCE_DIR}/userspace/libsanalyzer/src)
include_directories(${PROJECT_SOURCE_DIR}/userspace/dragent/src)
include_directories(${PROJECT_SOURCE_DIR}/userspace/userspace-shared/src)
include_directories(${PROJECT_BINARY_DIR}/userspace/draiosproto)
include_directories(${PROJECT_BINARY_DIR}/userspace/dragent/src)
include_directories(${PROJECT_BINARY_DIR}/userspace/engine)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/openssl-${DRAIOS_OPENSSL_VERSION}/target/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/poco-${DRAIOS_POCO_VERSION}/target/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/yaml-${DRAIOS_YAML_VERSION}/target/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/boost_${DRAIOS_BOOST_VERSION})
include_directories(${DRAIOS_DEPENDENCIES_DIR}/curl-${DRAIOS_CURL_VERSION}/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/gperftools-${DRAIOS_GPERFTOOLS_VERSION}/target/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/libb64-${DRAIOS_B64_VERSION}/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/jq-${DRAIOS_JQ_VERSION})
include_directories(${DRAIOS_DEPENDENCIES_DIR}/grpc-${DRAIOS_GRPC_VERSION}/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/tbb-${DRAIOS_TBB_VERSION}/include)


target_link_libraries(benchmark-dragent
    ${DRAIOS_DEPENDENCIES_DIR}/benchmark/build/src/libbenchmark.a
    ${DRAIOS_DEPENDENCIES_DIR}/benchmark/build/src/libbenchmark_main.a
    rt
    dragentl
    draiosproto
)

add_custom_target(run-benchmark-dragent
		COMMAND benchmark-dragent
)

install(TARGETS benchmark-dragent
    DESTINATION ${CMAKE_INSTALL_PREFIX}/test/
    COMPONENT tests)
