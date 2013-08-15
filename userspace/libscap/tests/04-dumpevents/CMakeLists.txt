include_directories(${PROJECT_SOURCE_DIR}/common)
include_directories(${PROJECT_SOURCE_DIR}/userspace/libscap)

add_executable(scap-dumpevents 
	test.c)

target_link_libraries(scap-dumpevents
	scap)

install(TARGETS scap-dumpevents
	DESTINATION ${DRAIOS_BIN_PREFIX}/bin
	COMPONENT tests)
