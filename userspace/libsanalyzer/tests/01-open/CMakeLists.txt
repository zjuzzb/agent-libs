include_directories(${PROJECT_SOURCE_DIR}/common)
include_directories(${PROJECT_SOURCE_DIR}/userspace/libscap)
include_directories(${PROJECT_SOURCE_DIR}/userspace/libsinsp)
include_directories(${PROJECT_SOURCE_DIR}/userspace/libsanalyzer)
add_definitions( -DHAS_ANALYZER )

add_executable(sinsp-open 
	test.cpp)

target_link_libraries(sinsp-open
	sanalyzer) 

install(TARGETS sinsp-open 
	DESTINATION ${DRAIOS_BIN_PREFIX}/bin
	COMPONENT tests)
