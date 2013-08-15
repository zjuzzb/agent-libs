include_directories(${PROJECT_SOURCE_DIR}/common)
include_directories(${PROJECT_SOURCE_DIR}/userspace/libscap)

add_executable(scap-stopcapture
	test.c)

target_link_libraries(scap-stopcapture
	scap)

install(TARGETS scap-stopcapture
	DESTINATION ${DRAIOS_BIN_PREFIX}/bin
	COMPONENT tests)
