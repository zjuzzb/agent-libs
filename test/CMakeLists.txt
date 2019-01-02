add_subdirectory(resources)
add_subdirectory(diff_pb)

include_directories(${PROJECT_SOURCE_DIR}/common)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/gtest-${DRAIOS_GTEST_VERSION}/fused-src/gtest)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/poco-${DRAIOS_POCO_VERSION}/target/include)
include_directories(${PROJECT_SOURCE_DIR}/../sysdig/driver)
include_directories(${PROJECT_SOURCE_DIR}/../sysdig/userspace/libscap)
include_directories(${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp)
include_directories(${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/third-party/jsoncpp)
include_directories(${PROJECT_SOURCE_DIR}/../oss-falco/userspace/engine)
include_directories(${PROJECT_SOURCE_DIR}/userspace)
include_directories(${PROJECT_SOURCE_DIR}/userspace/libsanalyzer)
include_directories(${PROJECT_SOURCE_DIR}/userspace/dragent)
include_directories(${PROJECT_BINARY_DIR}/userspace/dragent)
include_directories(${PROJECT_BINARY_DIR}/userspace/draiosproto)
include_directories(${PROJECT_BINARY_DIR}/userspace/engine)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/openssl-${DRAIOS_OPENSSL_VERSION}/target/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/boost_${DRAIOS_BOOST_VERSION})
include_directories(${DRAIOS_DEPENDENCIES_DIR}/simpleopt)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/zlib-${DRAIOS_ZLIB_VERSION})
include_directories(${DRAIOS_DEPENDENCIES_DIR}/protobuf-${DRAIOS_PROTOBUF_VERSION}/target/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/yaml-${DRAIOS_YAML_VERSION}/target/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/curl-${DRAIOS_CURL_VERSION}/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/jq-${DRAIOS_JQ_VERSION})
include_directories(${DRAIOS_DEPENDENCIES_DIR}/libb64-${DRAIOS_B64_VERSION}/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/grpc-${DRAIOS_GRPC_VERSION}/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/tbb-${DRAIOS_TBB_VERSION}/include)

add_definitions( -DHAS_ANALYZER )

add_executable(tests
	auid.cpp
	analyzer_test.cpp
	app_checks.cpp
	baseliner.cpp
	capture_to_file_test.cpp
	container.cpp
	container_image_splitting.cpp
	coclient_test.cpp
	compliance.cpp
	custom_container.cpp
	dns_manager.cpp
	docker_utils.cpp
	emit_tracers.cpp
	event_capture.cpp
	evttype_filter.cpp
	forking.cpp
	fs.cpp
	# infrastructure_state_test.cpp
	inf_state_test.cpp
	memdump.cpp
	metric_limits.cpp
	label_limits.cpp
	k8s_limits.cpp
	internal_metrics.cpp
	ipv6.cpp
	net.cpp
	paths.cpp
	pipe.cpp
	pgid.cpp
	prefix_search_test.cpp
	process.cpp
	percentile.cpp
	security_policies.cpp
	socketpair.cpp
	sql.cpp
	sys_call_test.cpp
	tcp_client_server.cpp
	tcp_client_server_ipv4_mapped.cpp
	thread_state.cpp
	threadinfo.cpp
	tracers.cpp
	udp_client_server.cpp
	unix_client_server.cpp
	unix_udp_client_server.cpp
	main.cpp
	yaml_configuration.cpp
	configuration_test.cpp
	statsd.cpp
	suppress_events.cpp
	jmx_proxy.cpp
	token_bucket_test.cpp
	user_event.cpp
	uri.cpp
	json_query.cpp
	nodriver.cpp
	userspace/dragent/blocking_queue.ut.cpp
	userspace/dragent/watchdog_runnable.ut.cpp
	userspace/dragent/logger.ut.cpp
	userspace/libsanalyzer/parser_http.ut.cpp)

target_link_libraries(tests
	pthread
	sanalyzer
	dragentl
	draiosproto
	falco_engine
	${DRAIOS_DEPENDENCIES_DIR}/poco-${DRAIOS_POCO_VERSION}/target/lib/libPocoNet.a
	${DRAIOS_DEPENDENCIES_DIR}/poco-${DRAIOS_POCO_VERSION}/target/lib/libPocoFoundation.a
	${DRAIOS_DEPENDENCIES_DIR}/gtest-${DRAIOS_GTEST_VERSION}/libgtest.a
	${DRAIOS_DEPENDENCIES_DIR}/zlib-${DRAIOS_ZLIB_VERSION}/libz.a
	${DRAIOS_DEPENDENCIES_DIR}/yaml-${DRAIOS_YAML_VERSION}/target/lib/libyaml-cpp.a
	${DRAIOS_DEPENDENCIES_DIR}/jq-${DRAIOS_JQ_VERSION}/.libs/libjq.a)

add_executable(test_helper
	test_helper.cpp)

target_link_libraries(test_helper
	pthread)

execute_process(COMMAND "uname" "-m" OUTPUT_VARIABLE ARCH OUTPUT_STRIP_TRAILING_WHITESPACE)

if("${CMAKE_SIZEOF_VOID_P}" EQUAL "8")
	add_executable(test_helper_32
		test_helper.cpp)
	if("${ARCH}" STREQUAL "s390x")
		set_target_properties(test_helper_32 PROPERTIES COMPILE_FLAGS "-m31" LINK_FLAGS "-m31")
	else("${ARCH}" STREQUAL "s390x")
		set_target_properties(test_helper_32 PROPERTIES COMPILE_FLAGS "-m32" LINK_FLAGS "-m32")
	endif("${ARCH}" STREQUAL "s390x")
	install(TARGETS test_helper_32
		DESTINATION ${CMAKE_INSTALL_PREFIX}/test/
		COMPONENT tests)
	target_link_libraries(test_helper_32
		pthread)
endif("${CMAKE_SIZEOF_VOID_P}" EQUAL "8")


file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/captures)

install(DIRECTORY 
	DESTINATION ${CMAKE_INSTALL_PREFIX}/test/captures
	COMPONENT tests)

install(TARGETS test_helper
	DESTINATION ${CMAKE_INSTALL_PREFIX}/test/
	COMPONENT tests)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/test_helper.sh
	${CMAKE_CURRENT_BINARY_DIR}/test_helper.sh
	COPYONLY)

install(FILES test_helper.sh
	DESTINATION ${CMAKE_INSTALL_PREFIX}/test/
	PERMISSIONS OWNER_EXECUTE OWNER_WRITE OWNER_READ
	COMPONENT tests)

install(TARGETS tests 
	DESTINATION ${CMAKE_INSTALL_PREFIX}/test/
	COMPONENT tests)
