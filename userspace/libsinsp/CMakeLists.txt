include_directories(${DRAIOS_DEPENDENCIES_DIR}/protobuf-2.5.0/src)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/zlib-1.2.8)
include_directories(${PROJECT_SOURCE_DIR}/common)
include_directories(${PROJECT_SOURCE_DIR}/userspace/libscap)

add_library(sinsp STATIC
	analyzer.cpp
	connectinfo.cpp 
	config.cpp 
	draios.pb.cc
	event.cpp
	fdinfo.cpp
	ifinfo.cpp
	internal_metrics.cpp
	logger.cpp
	parser_http.cpp
	parsers.cpp
	procinfo.cpp
	sinsp.cpp
	stats.cpp
	transactinfo.cpp
	utils.cpp)

target_link_libraries(sinsp 
	scap 
	${DRAIOS_DEPENDENCIES_DIR}/protobuf-2.5.0/src/.libs/libprotobuf.a) 

add_subdirectory(tests/01-open)
add_subdirectory(tests/02-stopcapture)
	