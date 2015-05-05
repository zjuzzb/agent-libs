include_directories(${PROJECT_SOURCE_DIR}/common)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/gtest-1.7.0/fused-src/gtest)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/poco-1.4.6p4-all/target/include)
include_directories(${PROJECT_SOURCE_DIR}/../sysdig/driver)
include_directories(${PROJECT_SOURCE_DIR}/../sysdig/userspace/libscap)
include_directories(${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp)
include_directories(${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/third-party/jsoncpp)
include_directories(${PROJECT_SOURCE_DIR}/userspace/libsanalyzer)
include_directories(${PROJECT_SOURCE_DIR}/userspace/dragent)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/openssl-1.0.1h/target/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/boost_1_57_0)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/simpleopt)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/zlib-1.2.8)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/protobuf-2.5.0/src)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/yaml-cpp-0.5.1/target/include)

add_definitions( -DHAS_ANALYZER )

add_executable(test 
	analyzer_test.cpp
	capture_to_file_test.cpp
	container.cpp
	event_capture.cpp
	forking.cpp
	fs.cpp
	net.cpp
	paths.cpp
	pipe.cpp
	process.cpp
	socketpair.cpp
	sql.cpp
	sys_call_test.cpp
	tcp_client_server.cpp
	tcp_client_server_ipv4_mapped.cpp
	udp_client_server.cpp
	unix_client_server.cpp
	unix_udp_client_server.cpp
	userevts.cpp
	main.cpp
	yaml_configuration.cpp jmx_proxy.cpp)

target_link_libraries(test
	pthread
	sanalyzer 
	${DRAIOS_DEPENDENCIES_DIR}/poco-1.4.6p4-all/target/lib/libPocoNet.a
	${DRAIOS_DEPENDENCIES_DIR}/poco-1.4.6p4-all/target/lib/libPocoFoundation.a
	${DRAIOS_DEPENDENCIES_DIR}/gtest-1.7.0/libgtest.a
	${DRAIOS_DEPENDENCIES_DIR}/zlib-1.2.8/libz.a
	${DRAIOS_DEPENDENCIES_DIR}/yaml-cpp-0.5.1/target/lib/libyaml-cpp.a)

add_executable(resources/forking_main_thread_exit
	resources/forking_main_thread_exit.c)

target_link_libraries(resources/forking_main_thread_exit
	pthread) 

add_executable(resources/forking_nested
	resources/forking_nested.c)

target_link_libraries(resources/forking_nested
	pthread) 

add_executable(resources/chname
	resources/chname.cpp)

target_link_libraries(resources/chname
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

install(TARGETS resources/forking_nested 
	DESTINATION ${DRAIOS_BIN_PREFIX}/test/resources
	COMPONENT tests)

install(TARGETS resources/chname 
	DESTINATION ${DRAIOS_BIN_PREFIX}/test/resources
	COMPONENT tests)
