include_directories(${PROJECT_SOURCE_DIR}/common)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/gtest-1.6.0/fused-src/gtest)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/poco-1.4.6p2-all/target/include)
include_directories(${PROJECT_SOURCE_DIR}/userspace/libscap)
include_directories(${PROJECT_SOURCE_DIR}/userspace/libsinsp)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/simpleopt)

add_executable(test 
	capture_to_file_test.cpp
	event_capture.cpp
	forking.cpp
	fs.cpp
	net.cpp
	paths.cpp
	pipe.cpp
	process.cpp
	socketpair.cpp
	sys_call_test.cpp
	tcp_client_server.cpp
	udp_client_server.cpp
	unix_client_server.cpp
	unix_udp_client_server.cpp
	main.cpp)

target_link_libraries(test
	pthread
	sinsp 
	${DRAIOS_DEPENDENCIES_DIR}/poco-1.4.6p2-all/target/lib/libPocoUtil.a
	${DRAIOS_DEPENDENCIES_DIR}/poco-1.4.6p2-all/target/lib/libPocoNet.a
	${DRAIOS_DEPENDENCIES_DIR}/poco-1.4.6p2-all/target/lib/libPocoXML.a
	${DRAIOS_DEPENDENCIES_DIR}/poco-1.4.6p2-all/target/lib/libPocoFoundation.a
	${DRAIOS_DEPENDENCIES_DIR}/gtest-1.6.0/libgtest.a) 

add_executable(resources/forking_main_thread_exit
	resources/forking_main_thread_exit.c)

target_link_libraries(resources/forking_main_thread_exit
	pthread) 

file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/captures)
file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/resources 
	DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

install(DIRECTORY 
	DESTINATION ${DRAIOS_BIN_PREFIX}/test/captures
	COMPONENT tests)
install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/resources 
	DESTINATION ${DRAIOS_BIN_PREFIX}/test
	COMPONENT tests)
install(TARGETS test 
	DESTINATION ${DRAIOS_BIN_PREFIX}/test/
	COMPONENT tests)
install(TARGETS resources/forking_main_thread_exit 
	DESTINATION ${DRAIOS_BIN_PREFIX}/test/resources
	COMPONENT tests)
