
file(COPY
		random-capture.scap
	DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        DESTINATION ${CMAKE_INSTALL_PREFIX}/test
        COMPONENT unit-test-libsanalyzer)

