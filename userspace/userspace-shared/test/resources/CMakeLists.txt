
file(COPY
		test.yaml
		test.default.yaml
		test_simple_config.yaml
	DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        DESTINATION ${CMAKE_INSTALL_PREFIX}/test
        COMPONENT tests)

