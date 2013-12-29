include_directories(${PROJECT_SOURCE_DIR}/common)
include_directories(${PROJECT_SOURCE_DIR}/userspace/libscap)
include_directories(${PROJECT_SOURCE_DIR}/userspace/libsinsp)

add_executable(sinsp-stopcapture
	test.cpp)

target_link_libraries(sinsp-stopcapture
	sinsp) 

install(TARGETS sinsp-stopcapture 
	DESTINATION ${DRAIOS_BIN_PREFIX}/bin
	COMPONENT tests)
