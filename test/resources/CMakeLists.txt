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
		fake_backend.key
		fake_backend.py
		jmx_fail.json
		jmx_ok.json
		jmx_segfault.json
		jmx_wrong_object.json
		statsite_output.txt
		tcp_client.py
		tcp_server.py
		test.default.yaml
		test.yaml
		unix_client.py
		unix_server.py
	DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

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
