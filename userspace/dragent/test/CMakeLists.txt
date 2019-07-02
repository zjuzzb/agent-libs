include_directories(${DRAIOS_DEPENDENCIES_DIR}/gtest-${DRAIOS_GTEST_VERSION}/fused-src/gtest)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/poco-${DRAIOS_POCO_VERSION}/target/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/zlib-${DRAIOS_ZLIB_VERSION})
include_directories(${PROJECT_SOURCE_DIR}/../sysdig/userspace/async)
include_directories(${PROJECT_SOURCE_DIR}/../sysdig/userspace/libscap)
include_directories(${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp)
include_directories(${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/third-party/jsoncpp)
include_directories(${PROJECT_SOURCE_DIR}/userspace)
include_directories(${PROJECT_SOURCE_DIR}/userspace/dragent/src)
include_directories(${PROJECT_BINARY_DIR}/userspace/dragent/src) # for dragent_config.h
include_directories(${PROJECT_BINARY_DIR}/userspace/draiosproto)
include_directories(${PROJECT_SOURCE_DIR}/userspace/librest/src)
include_directories(${PROJECT_SOURCE_DIR}/userspace/librest/test_helpers)
include_directories(${PROJECT_SOURCE_DIR}/userspace/libsanalyzer/src)
include_directories(${PROJECT_SOURCE_DIR}/userspace/libsanalyzer/test_helpers)
include_directories(${PROJECT_SOURCE_DIR}/userspace/userspace-shared/src)
include_directories(${PROJECT_SOURCE_DIR}/userspace/userspace-shared/test-helpers)
include_directories(${PROJECT_SOURCE_DIR}/userspace/test_helpers/src)
include_directories(${PROJECT_SOURCE_DIR}/userspace/fake-collector/src)
include_directories(${PROJECT_SOURCE_DIR}/../oss-falco/userspace/engine)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/openssl-${DRAIOS_OPENSSL_VERSION}/target/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/boost_${DRAIOS_BOOST_VERSION})
include_directories(${DRAIOS_DEPENDENCIES_DIR}/simpleopt)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/protobuf-${DRAIOS_PROTOBUF_VERSION}/target/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/yaml-${DRAIOS_YAML_VERSION}/target/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/curl-${DRAIOS_CURL_VERSION}/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/jq-${DRAIOS_JQ_VERSION})
include_directories(${DRAIOS_DEPENDENCIES_DIR}/libb64-${DRAIOS_B64_VERSION}/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/grpc-${DRAIOS_GRPC_VERSION}/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/tbb-${DRAIOS_TBB_VERSION}/include)

add_definitions( -DHAS_ANALYZER )

add_executable(unit-test-dragent
	main.cpp
	blocking_queue.ut.cpp
	configlist_rest_request_handler.ut.cpp
	config_data_rest_request_handler.ut.cpp
	config_rest_request_handler.ut.cpp
	crash_handler.ut.cpp
	dragent_memdump_logger.ut.cpp
	dragent_user_event_callback.ut.cpp
	faultlist_rest_request_handler.ut.cpp
	fault_rest_request_handler.ut.cpp
	logger.ut.cpp
	metrics_rest_request_handler.ut.cpp
	sinsp_worker.ut.cpp
	spinlock.ut.cpp
	watchdog_runnable.ut.cpp
	connection_manager.ut.cpp
)

target_link_libraries(unit-test-dragent
	sanalyzer
	dragentl
	draiosproto
	fake-collector-core
	librestl
	test_helpers
	test-helpers-librest
	test-helpers-libsanalyzer
	test-helpers-userspace-shared
	userspace-shared
	${DRAIOS_DEPENDENCIES_DIR}/gtest-${DRAIOS_GTEST_VERSION}/libgtest.a
)

target_compile_definitions(unit-test-dragent PUBLIC SYSDIG_TEST)

file(
	COPY valgrind/helgrind.suppressions
	DESTINATION ${CMAKE_CURRENT_BINARY_DIR}
)

if(RUN_UNIT_TEST_UNDER_CODE_COVERAGE)
	add_custom_target(run-unit-test-dragent
		DEPENDS unit-test-dragent
		COMMAND ${PROJECT_SOURCE_DIR}/scripts/code-coverage lcov ./unit-test-dragent dragent.lcov
	)
else()
	# Since dragentl includes tcmalloc, helgrind doesn't play well with it.
	# So we just run valgrind.
	add_custom_target(run-unit-test-dragent
		DEPENDS unit-test-dragent
		COMMAND valgrind --error-exitcode=1 --track-origins=yes --gen-suppressions=all ./unit-test-dragent
	)
endif()

install(TARGETS unit-test-dragent
	DESTINATION ${CMAKE_INSTALL_PREFIX}/test/
	COMPONENT tests)
