
add_subdirectory(userspace/dragent/test)
add_subdirectory(userspace/libsanalyzer/test)
add_subdirectory(userspace/libsanalyzer/tests)
add_subdirectory(userspace/libsanalyzer/test_helpers)
add_subdirectory(userspace/test_helpers/src)
add_subdirectory(userspace/test_helpers/test)

if(NOT CYGWIN)
	add_subdirectory(bench)
	add_subdirectory(test)
endif()

add_custom_target(run-unit-tests
	COMMAND $(MAKE) run-unit-test-testhelpers
	COMMAND $(MAKE) run-unit-test-dragent
	COMMAND $(MAKE) run-unit-test-libsanalyzer
)
