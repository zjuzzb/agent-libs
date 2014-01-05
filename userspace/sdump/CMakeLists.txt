include_directories(${PROJECT_SOURCE_DIR}/common)
include_directories(${PROJECT_SOURCE_DIR}/userspace/libscap)
include_directories(${PROJECT_SOURCE_DIR}/userspace/libsinsp)

add_executable(sdump
	chisel.cpp
	sdump.cpp)

target_link_libraries(sdump
	sinsp) 

install(TARGETS sdump 
	DESTINATION ${DRAIOS_BIN_PREFIX}/bin
	COMPONENT tests)
