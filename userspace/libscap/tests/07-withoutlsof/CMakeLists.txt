include_directories(${PROJECT_SOURCE_DIR}/common)
include_directories(${PROJECT_SOURCE_DIR}/userspace/libscap)

add_executable(scap-withoutlsof
	test.c)

target_link_libraries(scap-withoutlsof
	scap)

install(TARGETS scap-withoutlsof
	DESTINATION ${DRAIOS_BIN_PREFIX}/bin
	COMPONENT tests)
