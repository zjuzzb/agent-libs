
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

if(NOT CYGWIN)
	add_subdirectory(test)
endif()

# Run all unit tests
add_custom_target(run-unit-tests
	COMMAND $(MAKE) run-unit-test-testhelpers
	COMMAND $(MAKE) run-unit-test-dragent
	COMMAND $(MAKE) run-unit-test-libsanalyzer
)



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
