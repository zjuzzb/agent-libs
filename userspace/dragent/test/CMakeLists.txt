
include_directories(${DRAIOS_DEPENDENCIES_DIR}/gtest-${DRAIOS_GTEST_VERSION}/fused-src/gtest)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/poco-${DRAIOS_POCO_VERSION}/target/include)
include_directories(${PROJECT_SOURCE_DIR}/../sysdig/userspace/libscap)
include_directories(${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp)
include_directories(${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/third-party/jsoncpp)
include_directories(${PROJECT_SOURCE_DIR}/userspace)
include_directories(${PROJECT_SOURCE_DIR}/userspace/libsanalyzer)
include_directories(${PROJECT_SOURCE_DIR}/userspace/dragent/src)
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

add_definitions( -DHAS_ANALYZER )

add_executable(unit-test-dragent
	main.cpp
	blocking_queue.ut.cpp
	watchdog_runnable.ut.cpp
	logger.ut.cpp
)

target_link_libraries(unit-test-dragent
 	pthread
	sanalyzer
	dragentl
 	draiosproto
	falco_engine
	${DRAIOS_DEPENDENCIES_DIR}/poco-${DRAIOS_POCO_VERSION}/target/lib/libPocoNet.a
	${DRAIOS_DEPENDENCIES_DIR}/poco-${DRAIOS_POCO_VERSION}/target/lib/libPocoNetSSL.a
  ${DRAIOS_DEPENDENCIES_DIR}/poco-${DRAIOS_POCO_VERSION}/target/lib/libPocoFoundation.a
	${DRAIOS_DEPENDENCIES_DIR}/gtest-${DRAIOS_GTEST_VERSION}/libgtest.a
	${DRAIOS_DEPENDENCIES_DIR}/zlib-${DRAIOS_ZLIB_VERSION}/libz.a
	${DRAIOS_DEPENDENCIES_DIR}/yaml-${DRAIOS_YAML_VERSION}/target/lib/libyaml-cpp.a
	${DRAIOS_DEPENDENCIES_DIR}/jq-${DRAIOS_JQ_VERSION}/.libs/libjq.a
	${DRAIOS_DEPENDENCIES_DIR}/openssl-${DRAIOS_OPENSSL_VERSION}/target/lib/libssl.a
	${DRAIOS_DEPENDENCIES_DIR}/openssl-${DRAIOS_OPENSSL_VERSION}/target/lib/libcrypto.a
)

add_custom_target(run-unit-test-dragent
	COMMAND unit-test-dragent
)

install(TARGETS unit-test-dragent
	DESTINATION ${CMAKE_INSTALL_PREFIX}/test/
	COMPONENT unit-test-dragent)
