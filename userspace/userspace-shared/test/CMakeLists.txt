add_subdirectory(resources)

include_directories(${PROJECT_SOURCE_DIR}/userspace/userspace-shared/src)
include_directories(${PROJECT_SOURCE_DIR}/userspace/userspace-shared/test-helpers)
include_directories(${PROJECT_SOURCE_DIR}/userspace/test_helpers/src)
include_directories(${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/third-party/jsoncpp)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/gtest-${DRAIOS_GTEST_VERSION}/fused-src/gtest)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/poco-${DRAIOS_POCO_VERSION}/target/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/yaml-${DRAIOS_YAML_VERSION}/target/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/boost_${DRAIOS_BOOST_VERSION})

add_executable(unit-test-userspace-shared
	main.cpp
	configuration_manager.ut.cpp
	filter.ut.cpp
	scoped_config.ut.cpp
	scoped_configuration.ut.cpp
	type_config.ut.cpp
	yaml_configuration.ut.cpp
)

target_link_libraries(unit-test-userspace-shared
	userspace-shared
	rt
	test_helpers
	test-helpers-userspace-shared
	${DRAIOS_DEPENDENCIES_DIR}/poco-${DRAIOS_POCO_VERSION}/target/lib/libPocoFoundation.a
	${DRAIOS_DEPENDENCIES_DIR}/gtest-${DRAIOS_GTEST_VERSION}/libgtest.a
	${DRAIOS_DEPENDENCIES_DIR}/yaml-${DRAIOS_YAML_VERSION}/target/lib/libyaml-cpp.a
	pthread
)

file(
	COPY valgrind/helgrind.suppressions
	DESTINATION ${CMAKE_CURRENT_BINARY_DIR}
)

if(RUN_UNIT_TEST_UNDER_CODE_COVERAGE)
	add_custom_target(run-unit-test-userspace-shared
		DEPENDS unit-test-userspace-shared
		COMMAND ${PROJECT_SOURCE_DIR}/scripts/code-coverage lcov ./unit-test-userspace-shared userspace-shared.lcov
	)
else()
	# Valgrind's thread analyzer, helgrind, doesn't work well with the release
	# version of the unit test binary -- the backtraces that we want to suppress
	# don't match reality in the code.  Rather than add suppressions for these
	# unexpected backtraces, we'll run helgrind only for debug builds.
	if(CMAKE_BUILD_TYPE STREQUAL "Debug")
		add_custom_target(run-unit-test-userspace-shared
		DEPENDS unit-test-userspace-shared
			COMMAND valgrind --error-exitcode=1 --gen-suppressions=all --soname-synonyms=somalloc=tcmalloc ./unit-test-userspace-shared
			COMMAND valgrind --error-exitcode=1 --suppressions=./helgrind.suppressions --gen-suppressions=all --tool=helgrind --soname-synonyms=somalloc=tcmalloc ./unit-test-userspace-shared
		)
	else()
		add_custom_target(run-unit-test-userspace-shared
			DEPENDS unit-test-userspace-shared
			COMMAND valgrind --error-exitcode=1 --gen-suppressions=all --soname-synonyms=somalloc=tcmalloc ./unit-test-userspace-shared
		)
	endif()
endif()

install(TARGETS unit-test-userspace-shared
	DESTINATION ${CMAKE_INSTALL_PREFIX}/test/
	COMPONENT unit-test-userspace-shared)
