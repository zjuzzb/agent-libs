include_directories(${PROJECT_SOURCE_DIR}/userspace/librest/src)
include_directories(${PROJECT_SOURCE_DIR}/userspace/librest/test_helpers)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/gtest-${DRAIOS_GTEST_VERSION}/fused-src/gtest)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/poco-${DRAIOS_POCO_VERSION}/target/include)

add_executable(unit-test-librest
	main.cpp
	dummy_server_request.ut.cpp
	dummy_server_response.ut.cpp
	rest_exception.ut.cpp
	rest_request_handler.ut.cpp
	rest_request_handler_factory.ut.cpp
	rest_server.ut.cpp
)

target_link_libraries(unit-test-librest
	userspace-shared
	rt
	${DRAIOS_DEPENDENCIES_DIR}/gtest-${DRAIOS_GTEST_VERSION}/libgtest.a
	librestl
	test-helpers-librest
	pthread
)

file(
	COPY valgrind/helgrind.suppressions
	DESTINATION ${CMAKE_CURRENT_BINARY_DIR}
)

if(RUN_UNIT_TEST_UNDER_CODE_COVERAGE)
	add_custom_target(run-unit-test-librest
		DEPENDS unit-test-librest
		COMMAND ${PROJECT_SOURCE_DIR}/scripts/code-coverage lcov ./unit-test-librest librest.lcov
	)
else()
	# Valgrind's thread analyzer, helgrind, doesn't work well with the release
	# version of the unit test binary -- the backtraces that we want to suppress
	# don't match reality in the code.  Rather than add suppressions for these
	# unexpected backtraces, we'll run helgrind only for debug builds.
	if(CMAKE_BUILD_TYPE STREQUAL "Debug")
		add_custom_target(run-unit-test-librest
		DEPENDS unit-test-librest
			COMMAND valgrind --error-exitcode=1 --gen-suppressions=all --soname-synonyms=somalloc=tcmalloc ./unit-test-librest
			COMMAND valgrind --error-exitcode=1 --suppressions=./helgrind.suppressions --gen-suppressions=all --tool=helgrind --soname-synonyms=somalloc=tcmalloc ./unit-test-librest
		)
	else()
		add_custom_target(run-unit-test-librest
			DEPENDS unit-test-librest
			COMMAND valgrind --error-exitcode=1 --gen-suppressions=all --soname-synonyms=somalloc=tcmalloc ./unit-test-librest
		)
	endif()
endif()

install(TARGETS unit-test-librest
	DESTINATION ${CMAKE_INSTALL_PREFIX}/test/
	COMPONENT unit-test-librest
)
