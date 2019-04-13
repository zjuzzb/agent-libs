add_subdirectory(resources)

include_directories(${PROJECT_SOURCE_DIR}/userspace/userspace-shared/src)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/gtest-${DRAIOS_GTEST_VERSION}/fused-src/gtest)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/poco-${DRAIOS_POCO_VERSION}/target/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/yaml-${DRAIOS_YAML_VERSION}/target/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/boost_${DRAIOS_BOOST_VERSION})

add_executable(unit-test-userspace-shared
	main.cpp
	yaml_configuration.ut.cpp)

target_link_libraries(unit-test-userspace-shared
	userspace-shared
	pthread
	rt
	test_helpers
#	${DRAIOS_DEPENDENCIES_DIR}/poco-${DRAIOS_POCO_VERSION}/target/lib/libPocoNet.a
#	${DRAIOS_DEPENDENCIES_DIR}/poco-${DRAIOS_POCO_VERSION}/target/lib/libPocoNetSSL.a
	${DRAIOS_DEPENDENCIES_DIR}/poco-${DRAIOS_POCO_VERSION}/target/lib/libPocoFoundation.a
	${DRAIOS_DEPENDENCIES_DIR}/gtest-${DRAIOS_GTEST_VERSION}/libgtest.a
#	${DRAIOS_DEPENDENCIES_DIR}/zlib-${DRAIOS_ZLIB_VERSION}/libz.a
	${DRAIOS_DEPENDENCIES_DIR}/yaml-${DRAIOS_YAML_VERSION}/target/lib/libyaml-cpp.a
#	${DRAIOS_DEPENDENCIES_DIR}/jq-${DRAIOS_JQ_VERSION}/.libs/libjq.a
#	${DRAIOS_DEPENDENCIES_DIR}/openssl-${DRAIOS_OPENSSL_VERSION}/target/lib/libssl.a
#	${DRAIOS_DEPENDENCIES_DIR}/openssl-${DRAIOS_OPENSSL_VERSION}/target/lib/libcrypto.a
)

# Valgrind's thread analyzer, helgrind, doesn't work well with the release
# version of the unit test binary -- the backtraces that we want to suppress
# don't match reality in the code.  Rather than add suppressions for these
# unexpected backtraces, we'll run helgrind only for debug builds.
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
	add_custom_target(run-unit-test-userspace-shared
		COMMAND valgrind --gen-suppressions=all ./unit-test-userspace-shared
		COMMAND valgrind --suppressions=./helgrind.suppressions --gen-suppressions=all --tool=helgrind ./unit-test-userspace-shared
	)
else()
	add_custom_target(run-unit-test-userspace-shared
		COMMAND valgrind --gen-suppressions=all ./unit-test-userspace-shared
	)
endif()

install(TARGETS unit-test-userspace-shared
	DESTINATION ${CMAKE_INSTALL_PREFIX}/test/
	COMPONENT unit-test-userspace-shared)
