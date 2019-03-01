include_directories(${PROJECT_SOURCE_DIR}/common)
include_directories(${PROJECT_SOURCE_DIR}/userspace/libscap)
include_directories(${PROJECT_SOURCE_DIR}/userspace/libsinsp)
include_directories(${PROJECT_SOURCE_DIR}/userspace/libsanalyzer/src)
include_directories(${PROJECT_SOURCE_DIR}/../sysdig/userspace/libscap)
include_directories(${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/curl-${DRAIOS_CURL_VERSION}/include)
include_directories(${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/third-party/jsoncpp)
add_definitions( -DHAS_ANALYZER )

add_executable(sinsp-stopcapture
	test.cpp)

target_link_libraries(sinsp-stopcapture
	sanalyzer
	draiosproto
	pthread)

install(TARGETS sinsp-stopcapture 
	DESTINATION ${CMAKE_INSTALL_PREFIX}/bin
	COMPONENT tests)
