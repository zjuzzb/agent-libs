include_directories(${PROJECT_SOURCE_DIR}/../sysdig/common)
include_directories(${PROJECT_SOURCE_DIR}/../sysdig/userspace/libscap)
include_directories(${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp)
include_directories(${PROJECT_SOURCE_DIR}/userspace/libsanalyzer)
add_definitions( -DHAS_ANALYZER )

add_executable(sinsp-open 
	test.cpp)

target_link_libraries(sinsp-open
	sanalyzer
	draiosproto
	pthread)

if(CYGWIN)
target_link_libraries(sinsp-open
	/lib/w32api/libiphlpapi.a)
endif()

install(TARGETS sinsp-open 
	DESTINATION ${DRAIOS_BIN_PREFIX}/bin
	COMPONENT tests)
