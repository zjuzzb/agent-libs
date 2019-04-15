include_directories(${DRAIOS_DEPENDENCIES_DIR}/gtest-${DRAIOS_GTEST_VERSION}/fused-src/gtest)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/poco-${DRAIOS_POCO_VERSION}/target/include)
include_directories(../src)


include_directories(${CMAKE_CURRENT_BINARY_DIR})
include_directories(${DRAIOS_DEPENDENCIES_DIR}/protobuf-${DRAIOS_PROTOBUF_VERSION}/target/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/zlib-${DRAIOS_ZLIB_VERSION})
include_directories(${PROJECT_SOURCE_DIR}/../sysdig/userspace/async)
include_directories(${PROJECT_SOURCE_DIR}/../sysdig/userspace/libscap)
include_directories(${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp)
include_directories(${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/third-party/jsoncpp)
include_directories(${PROJECT_SOURCE_DIR}/userspace/libsanalyzer/src)
include_directories(${CMAKE_CURRENT_BINARY_DIR}/../../draiosproto)
include_directories(${PROJECT_SOURCE_DIR}/../oss-falco/userspace/engine)
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

add_definitions( -DHAS_ANALYZER )

add_executable(unit-test-testhelpers
	main.cpp
	scoped_file_descriptor.ut.cpp
	scoped_pipe.ut.cpp
	scoped_temp_directory.ut.cpp
	scoped_temp_file.ut.cpp
)

target_compile_definitions(unit-test-testhelpers PUBLIC DRAIOS_TEST)

if(CYGWIN)
	set(POCO_LIB_DIR "bin")
	set(POCO_LIB_PREFIX "cyg")
else()
	set(POCO_LIB_DIR "lib")
	set(POCO_LIB_PREFIX "lib")
endif()

target_link_libraries(unit-test-testhelpers
	test_helpers
	pthread
	rt
	sanalyzer.test
	${DRAIOS_DEPENDENCIES_DIR}/poco-${DRAIOS_POCO_VERSION}/target/${POCO_LIB_DIR}/${POCO_LIB_PREFIX}PocoFoundation.a
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
	add_custom_target(run-unit-test-testhelpers
		DEPENDS unit-test-testhelpers
		COMMAND valgrind --gen-suppressions=all ./unit-test-testhelpers
		COMMAND valgrind --suppressions=./helgrind.suppressions --gen-suppressions=all --tool=helgrind ./unit-test-testhelpers
	)
else()
	add_custom_target(run-unit-test-testhelpers
		DEPENDS unit-test-testhelpers
		COMMAND valgrind --gen-suppressions=all ./unit-test-testhelpers
	)
endif()

install(TARGETS unit-test-testhelpers
	DESTINATION ${CMAKE_INSTALL_PREFIX}/test/
	COMPONENT tests
)
