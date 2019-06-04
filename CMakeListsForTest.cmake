
add_subdirectory(userspace/dragent/benchmark)
add_subdirectory(userspace/dragent/test)
add_subdirectory(userspace/fake-collector/src)
add_subdirectory(userspace/libsanalyzer/benchmark)
add_subdirectory(userspace/libsanalyzer/test)
add_subdirectory(userspace/libsanalyzer/tests)
add_subdirectory(userspace/libsanalyzer/test_helpers)
add_subdirectory(userspace/test_helpers/src)
add_subdirectory(userspace/test_helpers/test)
add_subdirectory(userspace/userspace-shared/test)
add_subdirectory(userspace/userspace-shared/test-helpers)
add_subdirectory(userspace/librest/test)
add_subdirectory(userspace/librest/test_helpers)

if(NOT CYGWIN)
	add_subdirectory(test)
endif()

add_custom_target(run-unit-tests
	COMMAND $(MAKE) run-unit-test-testhelpers
	COMMAND $(MAKE) run-unit-test-dragent
	COMMAND $(MAKE) run-unit-test-libsanalyzer
	COMMAND $(MAKE) run-unit-test-librest
	COMMAND $(MAKE) run-unit-test-userspace-shared
)

# Run all unit tests
if(BUILD_FOR_COVERAGE)
	add_custom_target(clean-code-coverage
		COMMAND ${PROJECT_SOURCE_DIR}/scripts/code-coverage clean
	)

	add_custom_target(run-code-coverage
		COMMAND ${PROJECT_SOURCE_DIR}/scripts/code-coverage genhtml
	)
endif()

# Build all benchmarks.
add_custom_target(benchmarks
	DEPENDS benchmark-libsanalyzer
)

# Run all benchmarks
add_custom_target(run-benchmarks
  # benchmark-dragent needs a protobuf to get uploaded for it to be functional
	# COMMAND $(MAKE) run-benchmark-dragent
	COMMAND $(MAKE) run-benchmark-libsanalyzer
)
