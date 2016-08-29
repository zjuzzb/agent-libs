set(DRAIOS_OPENSSL_VERSION "1.0.2d")
set(DRAIOS_PROTOBUF_VERSION "2.5.0")
set(DRAIOS_ZLIB_VERSION "1.2.8")
set(DRAIOS_POCO_VERSION "1.4.6p4-all")
set(DRAIOS_LIBSSH_VERSION "0.7.2")
set(DRAIOS_YAML_VERSION "cpp-0.5.1")
set(DRAIOS_BOOST_VERSION "1_57_0")
set(DRAIOS_CURL_VERSION "7.45.0")

include_directories(${CMAKE_CURRENT_BINARY_DIR})
include_directories(${DRAIOS_DEPENDENCIES_DIR}/protobuf-${DRAIOS_PROTOBUF_VERSION}/src)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/zlib-${DRAIOS_ZLIB_VERSION})
include_directories(${PROJECT_SOURCE_DIR}/../sysdig/userspace/libscap)
include_directories(${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp)
include_directories(${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/third-party/jsoncpp)
include_directories(${PROJECT_SOURCE_DIR}/userspace/libsanalyzer)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/openssl-${DRAIOS_OPENSSL_VERSION}/target/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/poco-${DRAIOS_POCO_VERSION}/target/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/libssh-${DRAIOS_LIBSSH_VERSION}/target/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/yaml-${DRAIOS_YAML_VERSION}/target/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/boost_${DRAIOS_BOOST_VERSION})
include_directories(${DRAIOS_DEPENDENCIES_DIR}/curl-${DRAIOS_CURL_VERSION}/include)

add_definitions( -DHAS_ANALYZER )

add_executable(dragent
	configuration.cpp 
	connection_manager.cpp
	crash_handler.cpp
	dragent.cpp
	error_handler.cpp
	logger.cpp
	main.cpp
	monitor.cpp
	protocol.cpp
	sinsp_data_handler.cpp
	sinsp_worker.cpp
	ssh_worker.cpp
	update_worker.cpp
	subprocesses_logger.cpp
	user_event_channel.cpp)

target_link_libraries(dragent
	pthread
	sanalyzer
	${DRAIOS_DEPENDENCIES_DIR}/poco-${DRAIOS_POCO_VERSION}/target/lib/libPocoUtil.a
	${DRAIOS_DEPENDENCIES_DIR}/poco-${DRAIOS_POCO_VERSION}/target/lib/libPocoNet.a
	${DRAIOS_DEPENDENCIES_DIR}/poco-${DRAIOS_POCO_VERSION}/target/lib/libPocoNetSSL.a
	${DRAIOS_DEPENDENCIES_DIR}/poco-${DRAIOS_POCO_VERSION}/target/lib/libPocoCrypto.a
	${DRAIOS_DEPENDENCIES_DIR}/poco-${DRAIOS_POCO_VERSION}/target/lib/libPocoXML.a
	${DRAIOS_DEPENDENCIES_DIR}/poco-${DRAIOS_POCO_VERSION}/target/lib/libPocoFoundation.a
	${DRAIOS_DEPENDENCIES_DIR}/libssh-${DRAIOS_LIBSSH_VERSION}/target/lib/libssh.a
	${DRAIOS_DEPENDENCIES_DIR}/openssl-${DRAIOS_OPENSSL_VERSION}/target/lib/libssl.a
	${DRAIOS_DEPENDENCIES_DIR}/openssl-${DRAIOS_OPENSSL_VERSION}/target/lib/libcrypto.a
	rt
	${DRAIOS_DEPENDENCIES_DIR}/yaml-${DRAIOS_YAML_VERSION}/target/lib/libyaml-cpp.a)

file(COPY ${PROJECT_SOURCE_DIR}/scripts/debian/dragent
	DESTINATION ${PROJECT_BINARY_DIR}/scripts/debian)

file(COPY ${PROJECT_SOURCE_DIR}/scripts/rpm/dragent
	DESTINATION ${PROJECT_BINARY_DIR}/scripts/rpm)

file(COPY root.cert
	DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/dragent.default.yaml
	DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

file(COPY chisels
	DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

file(COPY ${PROJECT_SOURCE_DIR}/../sysdig/userspace/sysdig/chisels/common.lua
		${PROJECT_SOURCE_DIR}/../sysdig/userspace/sysdig/chisels/dkjson.lua
		DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/chisels)

install(TARGETS dragent 
	DESTINATION ${DRAIOS_BIN_PREFIX}/bin
	COMPONENT agent)

install(FILES root.cert 
	DESTINATION ${DRAIOS_BIN_PREFIX}
	COMPONENT agent)

install(FILES dragent.default.yaml
	DESTINATION ${DRAIOS_BIN_PREFIX}/etc
	COMPONENT agent)

install(DIRECTORY chisels
	DESTINATION ${DRAIOS_BIN_PREFIX}/share
	COMPONENT agent)

install(FILES ${PROJECT_SOURCE_DIR}/../sysdig/userspace/sysdig/chisels/common.lua
		${PROJECT_SOURCE_DIR}/../sysdig/userspace/sysdig/chisels/dkjson.lua
		DESTINATION ${DRAIOS_BIN_PREFIX}/share/chisels
		COMPONENT agent)

configure_file(config.h.in config.h)
