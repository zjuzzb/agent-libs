add_custom_target(resources-cointerface ALL DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/cointerface)
add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/cointerface
	COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_BINARY_DIR}/userspace/cointerface/cointerface ${CMAKE_CURRENT_BINARY_DIR}/cointerface
	DEPENDS cointerface)

install(PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/cointerface
	DESTINATION ${DRAIOS_BIN_PREFIX}/test/resources
	COMPONENT tests)

add_executable(forking_main_thread_exit
	forking_main_thread_exit.c)

target_link_libraries(forking_main_thread_exit
	pthread) 

add_executable(forking_nested
	forking_nested.c)

target_link_libraries(forking_nested
	pthread) 

add_executable(chname
	chname.cpp)

target_link_libraries(chname
	pthread)

file(COPY fake_backend.cert
		app_checks_ok.json
		fake_backend.key
		fake_backend.py
		jmx_fail.json
		jmx_ok.json
		jmx_segfault.json
		jmx_wrong_object.json
		security_policies_message.txt
		statsite_output.txt
		tcp_client.py
		tcp_server.py
		test.default.yaml
		test.yaml
		test_filters.yaml
		unix_client.py
		unix_server.py
	DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

file(COPY falco/falco_rules.default.yaml
  falco/falco_rules.yaml
  falco/match-system-rules.scap
  falco/match-user-rules.scap
  falco/match-nothing.scap
  DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/falco)

install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
	DESTINATION ${DRAIOS_BIN_PREFIX}/test
	COMPONENT tests)

install(TARGETS forking_main_thread_exit 
	DESTINATION ${DRAIOS_BIN_PREFIX}/test/resources
	COMPONENT tests)

install(TARGETS forking_nested 
	DESTINATION ${DRAIOS_BIN_PREFIX}/test/resources
	COMPONENT tests)

install(TARGETS chname 
	DESTINATION ${DRAIOS_BIN_PREFIX}/test/resources
	COMPONENT tests)

execute_process(COMMAND "uname" "-m" OUTPUT_VARIABLE ARCH OUTPUT_STRIP_TRAILING_WHITESPACE)

if("${CMAKE_SIZEOF_VOID_P}" EQUAL "8")
	add_executable(execve
		execve.c)
	install(TARGETS execve 
		DESTINATION ${DRAIOS_BIN_PREFIX}/test/resources
		COMPONENT tests)

	add_executable(execve32
		execve.c)
	install(TARGETS execve32
		DESTINATION ${DRAIOS_BIN_PREFIX}/test/resources
		COMPONENT tests)
        if("${ARCH}" STREQUAL "s390x")
		set_target_properties(execve32 PROPERTIES COMPILE_FLAGS "-m31" LINK_FLAGS "-m31")
        else("${ARCH}" STREQUAL "s390x")
		set_target_properties(execve32 PROPERTIES COMPILE_FLAGS "-m32" LINK_FLAGS "-m32")
        endif("${ARCH}" STREQUAL "s390x")

endif("${CMAKE_SIZEOF_VOID_P}" EQUAL "8")
