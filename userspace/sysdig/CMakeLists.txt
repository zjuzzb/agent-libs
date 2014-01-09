include_directories(${PROJECT_SOURCE_DIR}/common)
include_directories(${PROJECT_SOURCE_DIR}/userspace/libscap)
include_directories(${PROJECT_SOURCE_DIR}/userspace/libsinsp)
include_directories(.)

add_executable(sysdig
	chisel.cpp
	jsoncpp.cpp
	sysdig.cpp
	utils.cpp)

target_link_libraries(sysdig
	sinsp) 

install(TARGETS sysdig 
	DESTINATION ${DRAIOS_BIN_PREFIX}/bin
	COMPONENT tests)
