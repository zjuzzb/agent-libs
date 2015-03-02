include_directories(${CMAKE_CURRENT_BINARY_DIR})
include_directories(${DRAIOS_DEPENDENCIES_DIR}/protobuf-2.5.0/src)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/zlib-1.2.8)
include_directories(${PROJECT_SOURCE_DIR}/../sysdig/userspace/libscap)
include_directories(${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp)
include_directories(${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/third-party/jsoncpp)
include_directories(${PROJECT_SOURCE_DIR}/userspace/libsanalyzer)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/openssl-1.0.1h/target/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/poco-1.4.6p4-all/target/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/libssh-0.6.3/target/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/yaml-cpp-0.5.1/target/include)

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
	sdjagent_logger.cpp)

add_dependencies(dragent sdjagent sdjagentjni)

target_link_libraries(dragent
	pthread
	sanalyzer
	${DRAIOS_DEPENDENCIES_DIR}/poco-1.4.6p4-all/target/lib/libPocoUtil.a
	${DRAIOS_DEPENDENCIES_DIR}/poco-1.4.6p4-all/target/lib/libPocoNet.a
	${DRAIOS_DEPENDENCIES_DIR}/poco-1.4.6p4-all/target/lib/libPocoNetSSL.a
	${DRAIOS_DEPENDENCIES_DIR}/poco-1.4.6p4-all/target/lib/libPocoCrypto.a
	${DRAIOS_DEPENDENCIES_DIR}/poco-1.4.6p4-all/target/lib/libPocoXML.a
	${DRAIOS_DEPENDENCIES_DIR}/poco-1.4.6p4-all/target/lib/libPocoFoundation.a
	${DRAIOS_DEPENDENCIES_DIR}/libssh-0.6.3/target/lib/libssh.a
	${DRAIOS_DEPENDENCIES_DIR}/openssl-1.0.1h/target/lib/libssl.a
	${DRAIOS_DEPENDENCIES_DIR}/openssl-1.0.1h/target/lib/libcrypto.a
	dl
	rt
	${DRAIOS_DEPENDENCIES_DIR}/yaml-cpp-0.5.1/target/lib/libyaml-cpp.a)

file(COPY ${PROJECT_SOURCE_DIR}/scripts/debian/dragent
	DESTINATION ${PROJECT_BINARY_DIR}/scripts/debian)

file(COPY ${PROJECT_SOURCE_DIR}/scripts/rpm/dragent
	DESTINATION ${PROJECT_BINARY_DIR}/scripts/rpm)

file(COPY root.cert
	DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/dragent.default.yaml
          DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

install(TARGETS dragent 
	DESTINATION ${DRAIOS_BIN_PREFIX}/bin
	COMPONENT agent)

install(FILES root.cert 
	DESTINATION ${DRAIOS_BIN_PREFIX}
	COMPONENT agent)
install(FILES dragent.default.yaml
	DESTINATION ${DRAIOS_BIN_PREFIX}/etc
	COMPONENT agent)
configure_file(config.h.in config.h)
