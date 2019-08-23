add_custom_target(resources-cointerface ALL
	COMMAND ${CMAKE_COMMAND} -E copy_if_different ${CMAKE_BINARY_DIR}/userspace/cointerface/cointerface ${CMAKE_CURRENT_BINARY_DIR}/cointerface)
add_dependencies(resources-cointerface cointerface)

install(PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/cointerface
	DESTINATION ${CMAKE_INSTALL_PREFIX}/test/resources
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
		fake_docker.py
		jmx_fail.json
		jmx_ok.json
		jmx_segfault.json
		jmx_wrong_object.json
		tcp_client.py
		tcp_server.py
		test_filters.yaml
		unix_client.py
		unix_server.py
	DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/k8s_audit_events.txt
	${CMAKE_CURRENT_BINARY_DIR}/k8s_audit_events.txt
	COPYONLY)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/ipv6_traces/single_ipv6_conn.scap
	${CMAKE_CURRENT_BINARY_DIR}/ipv6_traces/single_ipv6_conn.scap
	COPYONLY)

install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
	DESTINATION ${CMAKE_INSTALL_PREFIX}/test
	COMPONENT tests)

install(TARGETS forking_main_thread_exit
	DESTINATION ${CMAKE_INSTALL_PREFIX}/test/resources
	COMPONENT tests)

install(TARGETS forking_nested
	DESTINATION ${CMAKE_INSTALL_PREFIX}/test/resources
	COMPONENT tests)

install(TARGETS chname
	DESTINATION ${CMAKE_INSTALL_PREFIX}/test/resources
	COMPONENT tests)

add_subdirectory(modules_dir)
add_subdirectory(health_dockerfiles)
add_subdirectory(security_policies_messages)

execute_process(COMMAND "uname" "-m" OUTPUT_VARIABLE ARCH OUTPUT_STRIP_TRAILING_WHITESPACE)

if("${CMAKE_SIZEOF_VOID_P}" EQUAL "8")
	add_executable(execve
		execve.c)
	install(TARGETS execve
		DESTINATION ${CMAKE_INSTALL_PREFIX}/test/resources
		COMPONENT tests)

	add_executable(execve32
		execve.c)
	install(TARGETS execve32
		DESTINATION ${CMAKE_INSTALL_PREFIX}/test/resources
		COMPONENT tests)
        if("${ARCH}" STREQUAL "s390x")
		set_target_properties(execve32 PROPERTIES COMPILE_FLAGS "-m31" LINK_FLAGS "-m31")
        else("${ARCH}" STREQUAL "s390x")
		set_target_properties(execve32 PROPERTIES COMPILE_FLAGS "-m32" LINK_FLAGS "-m32")
        endif("${ARCH}" STREQUAL "s390x")

endif("${CMAKE_SIZEOF_VOID_P}" EQUAL "8")

install(
		CODE "execute_process(
			COMMAND tar xzf ${CMAKE_CURRENT_SOURCE_DIR}/fake-proc.tar.gz
			WORKING_DIRECTORY ${CMAKE_INSTALL_PREFIX}/test/resources
		)"
		COMPONENT tests)
