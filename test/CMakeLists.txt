set(DRAIOS_OPENSSL_VERSION "1.0.2d")
set(DRAIOS_PROTOBUF_VERSION "2.5.0")
set(DRAIOS_ZLIB_VERSION "1.2.8")
set(DRAIOS_POCO_VERSION "1.4.6p4-all")
set(DRAIOS_GTEST_VERSION "1.7.0")
set(DRAIOS_YAML_VERSION "cpp-0.5.1")
set(DRAIOS_BOOST_VERSION "1_57_0")
set(DRAIOS_CURL_VERSION "7.45.0")

add_subdirectory(resources)

include_directories(${PROJECT_SOURCE_DIR}/common)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/gtest-${DRAIOS_GTEST_VERSION}/fused-src/gtest)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/poco-${DRAIOS_POCO_VERSION}/target/include)
include_directories(${PROJECT_SOURCE_DIR}/../sysdig/driver)
include_directories(${PROJECT_SOURCE_DIR}/../sysdig/userspace/libscap)
include_directories(${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp)
include_directories(${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/third-party/jsoncpp)
include_directories(${PROJECT_SOURCE_DIR}/userspace/libsanalyzer)
include_directories(${PROJECT_SOURCE_DIR}/userspace/dragent)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/openssl-${DRAIOS_OPENSSL_VERSION}/target/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/boost_${DRAIOS_BOOST_VERSION})
include_directories(${DRAIOS_DEPENDENCIES_DIR}/simpleopt)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/zlib-${DRAIOS_ZLIB_VERSION})
include_directories(${DRAIOS_DEPENDENCIES_DIR}/protobuf-${DRAIOS_PROTOBUF_VERSION}/src)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/yaml-${DRAIOS_YAML_VERSION}/target/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/curl-${DRAIOS_CURL_VERSION}/include)

add_definitions( -DHAS_ANALYZER )

add_executable(tests
	analyzer_test.cpp
	capture_to_file_test.cpp
	container.cpp
	event_capture.cpp
	forking.cpp
	fs.cpp
	tracers.cpp
	net.cpp
	paths.cpp
	pipe.cpp
	process.cpp
	socketpair.cpp
	sql.cpp
	sys_call_test.cpp
	tcp_client_server.cpp
	tcp_client_server_ipv4_mapped.cpp
	udp_client_server.cpp
	unix_client_server.cpp
	unix_udp_client_server.cpp
	main.cpp
	yaml_configuration.cpp
	statsd.cpp
	jmx_proxy.cpp)

target_link_libraries(tests
	pthread
	sanalyzer 
	${DRAIOS_DEPENDENCIES_DIR}/poco-${DRAIOS_POCO_VERSION}/target/lib/libPocoNet.a
	${DRAIOS_DEPENDENCIES_DIR}/poco-${DRAIOS_POCO_VERSION}/target/lib/libPocoFoundation.a
	${DRAIOS_DEPENDENCIES_DIR}/gtest-${DRAIOS_GTEST_VERSION}/libgtest.a
	${DRAIOS_DEPENDENCIES_DIR}/zlib-${DRAIOS_ZLIB_VERSION}/libz.a
	${DRAIOS_DEPENDENCIES_DIR}/yaml-${DRAIOS_YAML_VERSION}/target/lib/libyaml-cpp.a)

file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/captures)

install(DIRECTORY 
	DESTINATION ${DRAIOS_BIN_PREFIX}/test/captures
	COMPONENT tests)

install(TARGETS tests 
	DESTINATION ${DRAIOS_BIN_PREFIX}/test/
	COMPONENT tests)
