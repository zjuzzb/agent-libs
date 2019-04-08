
include_directories(${DRAIOS_DEPENDENCIES_DIR}/benchmark/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/poco-${DRAIOS_POCO_VERSION}/target/include)
include_directories(${PROJECT_SOURCE_DIR}/../sysdig/userspace/async)
include_directories(${PROJECT_SOURCE_DIR}/../sysdig/userspace/libscap)
include_directories(${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp)
include_directories(${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/third-party/jsoncpp)
include_directories(${PROJECT_SOURCE_DIR}/userspace)
include_directories(${PROJECT_SOURCE_DIR}/userspace/libsanalyzer/src)
include_directories(${PROJECT_SOURCE_DIR}/userspace/libsanalyzer/test_helpers)
include_directories(${PROJECT_BINARY_DIR}/userspace/dragent/src) # for dragent_config.h
include_directories(${PROJECT_BINARY_DIR}/userspace/draiosproto)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/openssl-${DRAIOS_OPENSSL_VERSION}/target/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/boost_${DRAIOS_BOOST_VERSION})
include_directories(${DRAIOS_DEPENDENCIES_DIR}/simpleopt)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/protobuf-${DRAIOS_PROTOBUF_VERSION}/target/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/yaml-${DRAIOS_YAML_VERSION}/target/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/curl-${DRAIOS_CURL_VERSION}/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/jq-${DRAIOS_JQ_VERSION})
include_directories(${DRAIOS_DEPENDENCIES_DIR}/libb64-${DRAIOS_B64_VERSION}/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/grpc-${DRAIOS_GRPC_VERSION}/include)

add_executable(benchmark-libsanalyzer
	analyzer.bm.cpp
	main.cpp)

add_definitions(-DHAS_ANALYZER)

target_link_libraries(benchmark-libsanalyzer
	sanalyzer.test
	draiosproto
	test-helpers-libsanalyzer
	${DRAIOS_DEPENDENCIES_DIR}/benchmark/build/src/libbenchmark.a
	${DRAIOS_DEPENDENCIES_DIR}/benchmark/build/src/libbenchmark_main.a
)

target_compile_definitions(benchmark-libsanalyzer PUBLIC SYSDIG_TEST)

add_custom_target(run-benchmark-libsanalyzer
		COMMAND benchmark-libsanalyzer
)

install(TARGETS benchmark-libsanalyzer
	DESTINATION ${CMAKE_INSTALL_PREFIX}/test/
	COMPONENT tests)
