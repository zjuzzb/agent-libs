include_directories(${DRAIOS_DEPENDENCIES_DIR}/protobuf-${DRAIOS_PROTOBUF_VERSION}/target/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/zlib-${DRAIOS_ZLIB_VERSION})
include_directories(${LUAJIT_INCLUDE})
include_directories(${DRAIOS_DEPENDENCIES_DIR}/curl-${DRAIOS_CURL_VERSION}/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/libb64-${DRAIOS_B64_VERSION}/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/openssl-${DRAIOS_OPENSSL_VERSION}/target/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/poco-${DRAIOS_POCO_VERSION}/target/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/jq-${DRAIOS_JQ_VERSION})
include_directories(${PROJECT_SOURCE_DIR}/../sysdig/common)
include_directories(${PROJECT_SOURCE_DIR}/../sysdig/userspace/libscap)
include_directories(${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp)
include_directories(${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/third-party/jsoncpp)
include_directories(${PROJECT_SOURCE_DIR}/userspace/libsanalyzer)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/yaml-${DRAIOS_YAML_VERSION}/target/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/boost_${DRAIOS_BOOST_VERSION})
include_directories(${DRAIOS_DEPENDENCIES_DIR}/grpc-${DRAIOS_GRPC_VERSION}/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/tbb-${DRAIOS_TBB_VERSION}/include)
include_directories(${CMAKE_CURRENT_BINARY_DIR}/../draiosproto)
include_directories(${CMAKE_CURRENT_BINARY_DIR})
include_directories(${DRAIOS_DEPENDENCIES_DIR}/gperftools-${DRAIOS_GPERFTOOLS_VERSION}/target/include)

if(CYGWIN)
include_directories("${WIN_HAL_INCLUDE}")
endif()

add_definitions( -DHAS_ANALYZER )
add_definitions(-DK8S_DISABLE_THREAD)

if (NOT CYGWIN)
	set(PROTOC LD_LIBRARY_PATH=${DRAIOS_DEPENDENCIES_DIR}/protobuf-${DRAIOS_PROTOBUF_VERSION}/target/lib
					   ${DRAIOS_DEPENDENCIES_DIR}/protobuf-${DRAIOS_PROTOBUF_VERSION}/target/bin/protoc)

	add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/cri.grpc.pb.cc
				${CMAKE_CURRENT_BINARY_DIR}/cri.grpc.pb.h
				${CMAKE_CURRENT_BINARY_DIR}/cri.pb.cc
				${CMAKE_CURRENT_BINARY_DIR}/cri.pb.h
			COMMENT "Generate CRI grpc code"
			DEPENDS ${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/cri.proto
			COMMAND ${PROTOC} -I ${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp --cpp_out=. ${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/cri.proto
			COMMAND ${PROTOC} -I ${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp --grpc_out=. --plugin=protoc-gen-grpc=${DRAIOS_DEPENDENCIES_DIR}/grpc-1.8.1/bins/opt/grpc_cpp_plugin ${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/cri.proto
			WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
endif()

set(SANALYZER_SOURCES
	analyzer.cpp
	analyzer_fd.cpp
	analyzer_parsers.cpp
	analyzer_thread.cpp
	analyzer_utils.cpp
	baseliner.cpp
	${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/chisel.cpp
	${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/chisel_api.cpp
	cm_quantile.c
	${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/cyclewriter.cpp
	connectinfo.cpp 
	config.cpp
	container_events/docker.cpp
	custom_container.cpp
	delays.cpp
	${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/container.cpp
	${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/container_engine/docker_common.cpp
	${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/container_info.cpp
	${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/dns_manager.cpp
	${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/dumper.cpp
	${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/event.cpp
	${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/eventformatter.cpp
	${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/fdinfo.cpp
	${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/filter.cpp
	${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/filterchecks.cpp
	${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/gen_filter.cpp
	heap.c
	${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/http_parser.c
	${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/http_reason.cpp
	${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/ifinfo.cpp
	infrastructure_state.cpp
	internal_metrics.cpp
	${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/internal_metrics.cpp
	${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/third-party/jsoncpp/jsoncpp.cpp
	${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/logger.cpp
	${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/lua_parser.cpp
	${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/lua_parser_api.cpp
	${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/prefix_search.cpp
	${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/tracers.cpp
	${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/uri_parser.c
	${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/uri.cpp
	${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/sinsp_auth.cpp
	${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/sinsp_curl.cpp
	${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/k8s.cpp
	${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/k8s_api_error.cpp
	${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/k8s_api_handler.cpp
	${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/k8s_component.cpp
	${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/k8s_daemonset_handler.cpp
	${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/k8s_deployment_handler.cpp
	${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/k8s_dispatcher.cpp
	${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/k8s_event_data.cpp
	${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/k8s_event_handler.cpp
	${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/k8s_handler.cpp
	${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/k8s_namespace_handler.cpp
	${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/k8s_net.cpp
	${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/k8s_node_handler.cpp
	${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/k8s_pod_handler.cpp
	${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/k8s_replicationcontroller_handler.cpp
	${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/k8s_replicaset_handler.cpp
	${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/k8s_service_handler.cpp
	${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/k8s_state.cpp
	${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/json_query.cpp
	${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/json_error_log.cpp
	k8s_proto.cpp
	k8s_delegator.cpp
	${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/marathon_component.cpp
	${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/marathon_http.cpp
	${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/mesos_auth.cpp
	${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/mesos.cpp
	${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/mesos_collector.cpp
	${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/mesos_component.cpp
	${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/mesos_http.cpp
	memdumper.cpp
	mesos_proto.cpp
	${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/mesos_state.cpp
	metric_limits.cpp
	metrics.cpp
	parser_http.cpp
	parser_mysql.cpp
	parser_postgres.cpp
	parser_mongodb.cpp
	parser_tls.cpp
	sqlparser.cpp
	${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/parsers.cpp
	percentile.cpp
	procfs_parser.cpp
	${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/protodecoder.cpp
	protostate.cpp
	${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/threadinfo.cpp
	sched_analyzer.cpp
	scores.cpp
	${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/sinsp.cpp
	${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/stats.cpp
	${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/stopwatch.cpp
	${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/token_bucket.cpp
	${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/tracer_emitter.cpp
	${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/tuples.cpp
	transactinfo.cpp
	${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/tuples.cpp
	${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/user_event.cpp
	${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/utils.cpp
	${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/value_parser.cpp
	${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/viewinfo.cpp
	jmx_proxy.cpp
	statsite_proxy.cpp
	app_checks.cpp
        proc_filter.cpp
	prometheus.cpp
	posix_queue.cpp
	coclient.cpp
	proc_config.h
	filter_limits.cpp
	mount_points_limits.cpp
	label_limits.cpp
	k8s_limits.cpp
	userdb.cpp
	blake2/blake2b.c
	env_hash.cpp)

if(NOT CYGWIN)
list(APPEND SANALYZER_SOURCES
	${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/cri.cpp
	${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/container_engine/cri.cpp
	${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/container_engine/docker_linux.cpp
	${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/container_engine/libvirt_lxc.cpp
	${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/container_engine/lxc.cpp
	${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/container_engine/mesos.cpp
	${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/container_engine/rkt.cpp

	${CMAKE_CURRENT_BINARY_DIR}/cri.grpc.pb.cc
	${CMAKE_CURRENT_BINARY_DIR}/cri.pb.cc
)
else()
list(APPEND SANALYZER_SOURCES
	${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/container_engine/docker_win.cpp)
endif()
add_library(sanalyzer STATIC ${SANALYZER_SOURCES})

add_dependencies(sanalyzer draiosproto)

if(CYGWIN)
	set(POCO_LIB_DIR "bin")
	set(POCO_LIB_PREFIX "cyg")
else()
	set(POCO_LIB_DIR "lib")
	set(POCO_LIB_PREFIX "lib")
endif()

if(NOT CYGWIN)
	target_link_libraries(sanalyzer
		scap
		${DRAIOS_DEPENDENCIES_DIR}/zlib-${DRAIOS_ZLIB_VERSION}/libz.a
		${LUALIB}
		${DRAIOS_DEPENDENCIES_DIR}/curl-${DRAIOS_CURL_VERSION}/lib/.libs/libcurl.a
		${DRAIOS_DEPENDENCIES_DIR}/c-ares-${DRAIOS_CARES_VERSION}/target/lib/libcares.a
		${DRAIOS_DEPENDENCIES_DIR}/libb64-${DRAIOS_B64_VERSION}/src/libb64.a
		${DRAIOS_DEPENDENCIES_DIR}/poco-${DRAIOS_POCO_VERSION}/target/${POCO_LIB_DIR}/${POCO_LIB_PREFIX}PocoNetSSL.a
		${DRAIOS_DEPENDENCIES_DIR}/poco-${DRAIOS_POCO_VERSION}/target/${POCO_LIB_DIR}/${POCO_LIB_PREFIX}PocoCrypto.a
		${DRAIOS_DEPENDENCIES_DIR}/poco-${DRAIOS_POCO_VERSION}/target/${POCO_LIB_DIR}/${POCO_LIB_PREFIX}PocoUtil.a
		${DRAIOS_DEPENDENCIES_DIR}/poco-${DRAIOS_POCO_VERSION}/target/${POCO_LIB_DIR}/${POCO_LIB_PREFIX}PocoNet.a
		${DRAIOS_DEPENDENCIES_DIR}/poco-${DRAIOS_POCO_VERSION}/target/${POCO_LIB_DIR}/${POCO_LIB_PREFIX}PocoFoundation.a
		${DRAIOS_DEPENDENCIES_DIR}/jq-${DRAIOS_JQ_VERSION}/.libs/libjq.a
		rt
		dl
		${DRAIOS_DEPENDENCIES_DIR}/openssl-${DRAIOS_OPENSSL_VERSION}/target/lib/libssl.a
		${DRAIOS_DEPENDENCIES_DIR}/openssl-${DRAIOS_OPENSSL_VERSION}/target/lib/libcrypto.a
		${DRAIOS_DEPENDENCIES_DIR}/gperftools-${DRAIOS_GPERFTOOLS_VERSION}/target/lib/libtcmalloc_and_profiler.a
		${DRAIOS_DEPENDENCIES_DIR}/yaml-${DRAIOS_YAML_VERSION}/target/lib/libyaml-cpp.a
		${DRAIOS_DEPENDENCIES_DIR}/tbb-${DRAIOS_TBB_VERSION}/build/lib_release/libtbb.a)
else()
	target_link_libraries(sanalyzer
		scap
		${DRAIOS_DEPENDENCIES_DIR}/zlib-${DRAIOS_ZLIB_VERSION}/libz.a
		${LUALIB}
		${DRAIOS_DEPENDENCIES_DIR}/curl-${DRAIOS_CURL_VERSION}/lib/.libs/libcurl.a
		${DRAIOS_DEPENDENCIES_DIR}/c-ares-${DRAIOS_CARES_VERSION}/target/lib/libcares.a
		${DRAIOS_DEPENDENCIES_DIR}/libb64-${DRAIOS_B64_VERSION}/src/libb64.a
		${DRAIOS_DEPENDENCIES_DIR}/poco-${DRAIOS_POCO_VERSION}/target/${POCO_LIB_DIR}/${POCO_LIB_PREFIX}PocoNetSSL.a
		${DRAIOS_DEPENDENCIES_DIR}/poco-${DRAIOS_POCO_VERSION}/target/${POCO_LIB_DIR}/${POCO_LIB_PREFIX}PocoCrypto.a
		${DRAIOS_DEPENDENCIES_DIR}/poco-${DRAIOS_POCO_VERSION}/target/${POCO_LIB_DIR}/${POCO_LIB_PREFIX}PocoUtil.a
		${DRAIOS_DEPENDENCIES_DIR}/poco-${DRAIOS_POCO_VERSION}/target/${POCO_LIB_DIR}/${POCO_LIB_PREFIX}PocoNet.a
		${DRAIOS_DEPENDENCIES_DIR}/poco-${DRAIOS_POCO_VERSION}/target/${POCO_LIB_DIR}/${POCO_LIB_PREFIX}PocoFoundation.a
		${DRAIOS_DEPENDENCIES_DIR}/jq-${DRAIOS_JQ_VERSION}/.libs/libjq.a
		rt
		dl
		${DRAIOS_DEPENDENCIES_DIR}/openssl-${DRAIOS_OPENSSL_VERSION}/target/lib/libssl.a
		${DRAIOS_DEPENDENCIES_DIR}/openssl-${DRAIOS_OPENSSL_VERSION}/target/lib/libcrypto.a
		${DRAIOS_DEPENDENCIES_DIR}/yaml-${DRAIOS_YAML_VERSION}/target/lib/libyaml-cpp.a)
endif()

if(NOT CYGWIN)
	target_link_libraries(sanalyzer anl)
endif()

add_subdirectory(tests/01-open)
add_subdirectory(tests/02-stopcapture)
