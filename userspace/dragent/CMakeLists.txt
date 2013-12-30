include_directories(${DRAIOS_DEPENDENCIES_DIR}/protobuf-2.5.0/src)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/zlib-1.2.8)
include_directories(${PROJECT_SOURCE_DIR}/userspace/libscap)
include_directories(${PROJECT_SOURCE_DIR}/userspace/libsinsp)
include_directories(${PROJECT_SOURCE_DIR}/userspace/libsanalyzer)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/openssl-1.0.1e/target/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/poco-1.4.6p2-all/target/include)
add_definitions( -DHAS_ANALYZER )

add_executable(dragent
	configuration.cpp 
	connection_manager.cpp
	crash_handler.cpp
	dumper_worker.cpp
	error_handler.cpp
	logger.cpp
	main.cpp
	protocol.cpp
	sinsp_data_handler.cpp)

target_link_libraries(dragent
	pthread
	sanalyzer
	${DRAIOS_DEPENDENCIES_DIR}/poco-1.4.6p2-all/target/lib/libPocoUtil.a
	${DRAIOS_DEPENDENCIES_DIR}/poco-1.4.6p2-all/target/lib/libPocoNet.a
	${DRAIOS_DEPENDENCIES_DIR}/poco-1.4.6p2-all/target/lib/libPocoNetSSL.a
	${DRAIOS_DEPENDENCIES_DIR}/poco-1.4.6p2-all/target/lib/libPocoCrypto.a
	${DRAIOS_DEPENDENCIES_DIR}/poco-1.4.6p2-all/target/lib/libPocoXML.a
	${DRAIOS_DEPENDENCIES_DIR}/poco-1.4.6p2-all/target/lib/libPocoFoundation.a
	${DRAIOS_DEPENDENCIES_DIR}/openssl-1.0.1e/target/lib/libssl.a
	${DRAIOS_DEPENDENCIES_DIR}/openssl-1.0.1e/target/lib/libcrypto.a)

file(COPY ${PROJECT_SOURCE_DIR}/scripts/debian/dragent
	DESTINATION ${PROJECT_BINARY_DIR}/scripts/debian)

file(COPY ${PROJECT_SOURCE_DIR}/scripts/rpm/dragent
	DESTINATION ${PROJECT_BINARY_DIR}/scripts/rpm)

file(COPY root.cert
	DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

install(TARGETS dragent 
	DESTINATION ${DRAIOS_BIN_PREFIX}/bin
	COMPONENT agent)

install(FILES root.cert 
	DESTINATION ${DRAIOS_BIN_PREFIX}
	COMPONENT agent)
