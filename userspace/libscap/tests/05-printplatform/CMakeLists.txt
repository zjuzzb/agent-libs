include_directories(${PROJECT_SOURCE_DIR}/common)
include_directories(${PROJECT_SOURCE_DIR}/userspace/libscap)

add_executable(scap-printplatform
	test.c)

target_link_libraries(scap-printplatform
	scap)

install(TARGETS scap-printplatform
	DESTINATION ${DRAIOS_BIN_PREFIX}/bin
	COMPONENT tests)
