include_directories(${DRAIOS_DEPENDENCIES_DIR}/gtest-${DRAIOS_GTEST_VERSION}/fused-src/gtest)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/poco-${DRAIOS_POCO_VERSION}/target/include)
include_directories(${PROJECT_SOURCE_DIR}/../sysdig/userspace/async)
include_directories(${PROJECT_SOURCE_DIR}/../sysdig/userspace/libscap)
include_directories(${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp)
include_directories(${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/third-party/jsoncpp)
include_directories(${PROJECT_SOURCE_DIR}/userspace)
include_directories(${PROJECT_SOURCE_DIR}/userspace/libsanalyzer/src)
include_directories(${PROJECT_SOURCE_DIR}/userspace/userspace-shared/src)
include_directories(${PROJECT_SOURCE_DIR}/userspace/userspace-shared/test-helpers)
include_directories(${PROJECT_SOURCE_DIR}/userspace/libsanalyzer/test_helpers)
include_directories(${PROJECT_BINARY_DIR}/userspace/dragent/src) # for dragent_config.h
include_directories(${PROJECT_BINARY_DIR}/userspace/draiosproto)
include_directories(${PROJECT_SOURCE_DIR}/userspace/test_helpers/src)
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

list(APPEND libsanalyzer_test_helpers_uts
	event_builder.ut.cpp
	sinsp_mock.ut.cpp
)

list(APPEND libsanalyzer_uts
	analyzer_file_stat.ut.cpp
	analyzer.ut.cpp
	main.cpp
	metric_serializer.ut.cpp
	metric_forwarding_configuration.ut.cpp
	mounted_fs.ut.cpp
	object_filter.ut.cpp
	parser_http.ut.cpp
	process_emitter.ut.cpp
	process_manager.ut.cpp
	protobuf_metric_serializer.ut.cpp
)

# We test both the libanalyzer itself and its test helpers in this library
add_executable(unit-test-libsanalyzer
		${libsanalyzer_test_helpers_uts}
		${libsanalyzer_uts})

target_link_libraries(unit-test-libsanalyzer
	sanalyzer.test
	draiosproto
	test-helpers-libsanalyzer
	test-helpers-userspace-shared
	test_helpers
	${DRAIOS_DEPENDENCIES_DIR}/gtest-${DRAIOS_GTEST_VERSION}/libgtest.a
)

target_compile_definitions(unit-test-libsanalyzer PUBLIC SYSDIG_TEST)

file(
	COPY valgrind/helgrind.suppressions
	DESTINATION ${CMAKE_CURRENT_BINARY_DIR}
)

if(BUILD_FOR_COVERAGE)
	add_custom_target(run-unit-test-libsanalyzer
		DEPENDS unit-test-libsanalyzer
		COMMAND ${PROJECT_SOURCE_DIR}/scripts/code-coverage lcov ./unit-test-libsanalyzer libsanalyzer.lcov
	)
else()
	# Valgrind's thread analyzer, helgrind, doesn't work well with the release
	# version of the unit test binary -- the backtraces that we want to suppress
	# don't match reality in the code.  Rather than add suppressions for these
	# unexpected backtraces, we'll run helgrind only for debug builds.
	if(CMAKE_BUILD_TYPE STREQUAL "Debug")
		add_custom_target(run-unit-test-libsanalyzer
			DEPENDS unit-test-libsanalyzer
			COMMAND valgrind --error-exitcode=1 --track-origins=yes --gen-suppressions=all  ./unit-test-libsanalyzer
			COMMAND valgrind --error-exitcode=1 --suppressions=./helgrind.suppressions --gen-suppressions=all --tool=helgrind --soname-synonyms=somalloc=tcmalloc ./unit-test-libsanalyzer
		)
	else()
		add_custom_target(run-unit-test-libsanalyzer
			DEPENDS unit-test-libsanalyzer
			COMMAND valgrind --error-exitcode=1 --track-origins=yes --gen-suppressions=all ./unit-test-libsanalyzer
		)
	endif()
endif()

install(TARGETS unit-test-libsanalyzer
	DESTINATION ${CMAKE_INSTALL_PREFIX}/test/
	COMPONENT tests)
