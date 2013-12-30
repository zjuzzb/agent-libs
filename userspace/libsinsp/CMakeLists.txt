include_directories(${DRAIOS_DEPENDENCIES_DIR}/protobuf-2.5.0/src)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/zlib-1.2.8)
include_directories(${PROJECT_SOURCE_DIR}/common)
include_directories(${PROJECT_SOURCE_DIR}/userspace/libscap)

add_library(sinsp STATIC
	event.cpp
	eventformatter.cpp
	fdinfo.cpp
	filter.cpp
	filterchecks.cpp
	ifinfo.cpp
	internal_metrics.cpp
	logger.cpp
	parsers.cpp
	threadinfo.cpp
	sinsp.cpp
	stats.cpp
	utils.cpp)

target_link_libraries(sinsp 
	scap)

	