include_directories(${DRAIOS_DEPENDENCIES_DIR}/gtest-${DRAIOS_GTEST_VERSION}/fused-src/gtest)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/poco-${DRAIOS_POCO_VERSION}/target/include)
include_directories(../src)

add_executable(unit-test-testhelpers
	main.cpp
	scoped_file_descriptor.ut.cpp
	scoped_pipe.ut.cpp
	scoped_temp_file.ut.cpp
)

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
		COMMAND valgrind --gen-suppressions=all ./unit-test-testhelpers
		COMMAND valgrind --suppressions=./helgrind.suppressions --gen-suppressions=all --tool=helgrind ./unit-test-testhelpers
	)
else()
	add_custom_target(run-unit-test-testhelpers
		COMMAND valgrind --gen-suppressions=all ./unit-test-testhelpers
	)
endif()

install(TARGETS unit-test-testhelpers
	DESTINATION ${CMAKE_INSTALL_PREFIX}/test/
	COMPONENT unit-test-testhelpers
)
