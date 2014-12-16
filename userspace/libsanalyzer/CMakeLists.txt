include_directories(${DRAIOS_DEPENDENCIES_DIR}/protobuf-2.5.0/src)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/zlib-1.2.8)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/LuaJIT-2.0.3/src)
include_directories(${PROJECT_SOURCE_DIR}/../sysdig/common)
include_directories(${PROJECT_SOURCE_DIR}/../sysdig/userspace/libscap)
include_directories(${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp)
include_directories(${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/third-party/jsoncpp)
include_directories(${PROJECT_SOURCE_DIR}/userspace/libsanalyzer)
add_definitions( -DHAS_ANALYZER )

add_library(sanalyzer STATIC
	analyzer.cpp
	analyzer_fd.cpp
	analyzer_parsers.cpp
	analyzer_thread.cpp
	analyzer_utils.cpp
	${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/chisel.cpp
	${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/cyclewriter.cpp
	connectinfo.cpp 
	config.cpp
	delays.cpp	
	draios.pb.cc
	${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/dumper.cpp
	${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/event.cpp
	${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/eventformatter.cpp
	${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/fdinfo.cpp
	${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/filter.cpp
	${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/filterchecks.cpp
	${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/ifinfo.cpp
	${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/internal_metrics.cpp
	${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/third-party/jsoncpp/jsoncpp.cpp
	${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/logger.cpp
	metrics.cpp
	parser_http.cpp
	parser_mysql.cpp
	parser_postgres.cpp
  parser_mongodb.cpp
	sqlparser.cpp
	${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/parsers.cpp
	procfs_parser.cpp
	${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/protodecoder.cpp
	protostate.cpp
	${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/threadinfo.cpp
	sched_analyzer.cpp
	scores.cpp
	${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/sinsp.cpp
	${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/stats.cpp
	transactinfo.cpp
	${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/utils.cpp)

target_link_libraries(sanalyzer
	scap 
	${DRAIOS_DEPENDENCIES_DIR}/protobuf-2.5.0/src/.libs/libprotobuf.a
	${DRAIOS_DEPENDENCIES_DIR}/zlib-1.2.8/libz.a
	${DRAIOS_DEPENDENCIES_DIR}/LuaJIT-2.0.3/src/libluajit.a)

add_subdirectory(tests/01-open)
add_subdirectory(tests/02-stopcapture)
	
