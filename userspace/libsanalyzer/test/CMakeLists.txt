include_directories(${DRAIOS_DEPENDENCIES_DIR}/gtest-${DRAIOS_GTEST_VERSION}/fused-src/gtest)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/poco-${DRAIOS_POCO_VERSION}/target/include)
include_directories(${PROJECT_SOURCE_DIR}/../sysdig/userspace/libscap)
include_directories(${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp)
include_directories(${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/third-party/jsoncpp)
include_directories(${PROJECT_SOURCE_DIR}/userspace)
include_directories(${PROJECT_SOURCE_DIR}/userspace/libsanalyzer/src)
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

add_executable(unit-test-libsanalyzer
	main.cpp
	parser_http.ut.cpp
)

target_link_libraries(unit-test-libsanalyzer
	sanalyzer
	draiosproto
	${DRAIOS_DEPENDENCIES_DIR}/gtest-${DRAIOS_GTEST_VERSION}/libgtest.a
)

file(
	COPY valgrind/helgrind.suppressions
	DESTINATION ${CMAKE_CURRENT_BINARY_DIR}
)

# Valgrind's thread analyzer, helgrind, doesn't work well with the release
# version of the unit test binary -- the backtraces that we want to suppress
# don't match reality in the code.  Rather than add suppressions for these
# unexpected backtraces, we'll run helgrind only for debug builds.
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
	add_custom_target(run-unit-test-libsanalyzer
		COMMAND valgrind --gen-suppressions=all ./unit-test-libsanalyzer
		COMMAND valgrind --suppressions=./helgrind.suppressions --gen-suppressions=all --tool=helgrind ./unit-test-libsanalyzer
	)
else()
	add_custom_target(run-unit-test-libsanalyzer
		COMMAND valgrind --gen-suppressions=all ./unit-test-libsanalyzer
	)
endif()

install(TARGETS unit-test-libsanalyzer
	DESTINATION ${CMAKE_INSTALL_PREFIX}/test/
	COMPONENT unit-test-libsanalyzer)
