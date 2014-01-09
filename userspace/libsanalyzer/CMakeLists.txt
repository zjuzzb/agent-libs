include_directories(${DRAIOS_DEPENDENCIES_DIR}/protobuf-2.5.0/src)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/zlib-1.2.8)
include_directories(${PROJECT_SOURCE_DIR}/common)
include_directories(${PROJECT_SOURCE_DIR}/userspace/libscap)
include_directories(${PROJECT_SOURCE_DIR}/userspace/libsinsp)
include_directories(${PROJECT_SOURCE_DIR}/userspace/libsanalyzer)
add_definitions( -DHAS_ANALYZER )

add_library(sanalyzer STATIC
	analyzer.cpp
	analyzer_fd.cpp
	analyzer_thread.cpp
	connectinfo.cpp 
	config.cpp
	delays.cpp	
	draios.pb.cc
	${PROJECT_SOURCE_DIR}/userspace/libsinsp/dumper.cpp
	${PROJECT_SOURCE_DIR}/userspace/libsinsp/event.cpp
	${PROJECT_SOURCE_DIR}/userspace/libsinsp/eventformatter.cpp
	${PROJECT_SOURCE_DIR}/userspace/libsinsp/fdinfo.cpp
	${PROJECT_SOURCE_DIR}/userspace/libsinsp/filter.cpp
	${PROJECT_SOURCE_DIR}/userspace/libsinsp/filterchecks.cpp
	${PROJECT_SOURCE_DIR}/userspace/libsinsp/ifinfo.cpp
	${PROJECT_SOURCE_DIR}/userspace/libsinsp/internal_metrics.cpp
	${PROJECT_SOURCE_DIR}/userspace/libsinsp/logger.cpp
	metrics.cpp
	parser_http.cpp
	${PROJECT_SOURCE_DIR}/userspace/libsinsp/parsers.cpp
	procfs_parser.cpp
	${PROJECT_SOURCE_DIR}/userspace/libsinsp/threadinfo.cpp
	sched_analyzer.cpp
	scores.cpp
	${PROJECT_SOURCE_DIR}/userspace/libsinsp/sinsp.cpp
	${PROJECT_SOURCE_DIR}/userspace/libsinsp/stats.cpp
	transactinfo.cpp
	${PROJECT_SOURCE_DIR}/userspace/libsinsp/utils.cpp)

target_link_libraries(sanalyzer
	scap 
	${DRAIOS_DEPENDENCIES_DIR}/protobuf-2.5.0/src/.libs/libprotobuf.a
	${DRAIOS_DEPENDENCIES_DIR}/zlib-1.2.8/libz.a)

add_subdirectory(tests/01-open)
add_subdirectory(tests/02-stopcapture)
	