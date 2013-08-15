include_directories(${PROJECT_SOURCE_DIR}/common)
include_directories(${PROJECT_SOURCE_DIR}/userspace/libscap)

add_executable(scap-checktimestamps
	test.c)

target_link_libraries(scap-checktimestamps
	scap)

install(TARGETS scap-checktimestamps
	DESTINATION ${DRAIOS_BIN_PREFIX}/bin
	COMPONENT tests)
