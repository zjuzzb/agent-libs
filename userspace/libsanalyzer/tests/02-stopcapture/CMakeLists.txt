include_directories(${PROJECT_SOURCE_DIR}/common)
include_directories(${PROJECT_SOURCE_DIR}/userspace/libscap)
include_directories(${PROJECT_SOURCE_DIR}/userspace/libsinsp)
include_directories(${PROJECT_SOURCE_DIR}/userspace/libsanalyzer)
add_definitions( -DHAS_ANALYZER )

add_executable(sinsp-stopcapture
	test.cpp)

target_link_libraries(sinsp-stopcapture
	pthread
	sanalyzer)

install(TARGETS sinsp-stopcapture 
	DESTINATION ${DRAIOS_BIN_PREFIX}/bin
	COMPONENT tests)
