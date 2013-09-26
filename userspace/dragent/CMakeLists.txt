include_directories(${DRAIOS_DEPENDENCIES_DIR}/protobuf-2.5.0/src)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/zlib-1.2.8)
include_directories(${PROJECT_SOURCE_DIR}/userspace/libscap)
include_directories(${PROJECT_SOURCE_DIR}/userspace/libsinsp)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/poco-1.4.6p1/target/include)

add_executable(dragent
	configuration.cpp 
	main.cpp)

target_link_libraries(dragent
	pthread
	sinsp
	${DRAIOS_DEPENDENCIES_DIR}/poco-1.4.6p1/target/lib/libPocoUtil.a
	${DRAIOS_DEPENDENCIES_DIR}/poco-1.4.6p1/target/lib/libPocoNet.a
	${DRAIOS_DEPENDENCIES_DIR}/poco-1.4.6p1/target/lib/libPocoXML.a
	${DRAIOS_DEPENDENCIES_DIR}/poco-1.4.6p1/target/lib/libPocoFoundation.a)

file(COPY ${PROJECT_SOURCE_DIR}/scripts/debian/dragent
	DESTINATION ${PROJECT_BINARY_DIR}/scripts/debian)

file(COPY ${PROJECT_SOURCE_DIR}/scripts/rpm/dragent
	DESTINATION ${PROJECT_BINARY_DIR}/scripts/rpm)

install(TARGETS dragent 
	DESTINATION ${DRAIOS_BIN_PREFIX}/bin
	COMPONENT agent)
