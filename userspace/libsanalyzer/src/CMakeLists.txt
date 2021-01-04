include_directories(${DRAIOS_DEPENDENCIES_DIR}/gtest-${DRAIOS_GTEST_VERSION}/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/protobuf-${DRAIOS_PROTOBUF_VERSION}/target/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/zlib-${DRAIOS_ZLIB_VERSION})
include_directories(${LUAJIT_INCLUDE})
include_directories(${DRAIOS_DEPENDENCIES_DIR}/curl-${DRAIOS_CURL_VERSION}/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/libb64-${DRAIOS_B64_VERSION}/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/openssl-${DRAIOS_OPENSSL_VERSION}/target/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/poco-${DRAIOS_POCO_VERSION}/target/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/jq-${DRAIOS_JQ_VERSION})
include_directories(${LIBSCAP_INCLUDE_DIR})
include_directories(${LIBSINSP_INCLUDE_DIRS})
include_directories(${PROJECT_SOURCE_DIR}/userspace/libsanalyzer/src)
include_directories(${PROJECT_SOURCE_DIR}/userspace/userspace-shared/src)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/yaml-${DRAIOS_YAML_VERSION}/target/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/boost_${DRAIOS_BOOST_VERSION})
include_directories(${DRAIOS_DEPENDENCIES_DIR}/grpc-${DRAIOS_GRPC_VERSION}/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/tbb-${DRAIOS_TBB_VERSION}/include)
include_directories(${CMAKE_CURRENT_BINARY_DIR}/../../draiosproto)
include_directories(${CMAKE_CURRENT_BINARY_DIR})
include_directories(${CMAKE_CURRENT_BINARY_DIR}/../../userspace-shared/src)
include_directories(${PROJECT_BINARY_DIR}/driver/src)
include_directories(
    ${DRAIOS_DEPENDENCIES_DIR}/gperftools-${DRAIOS_GPERFTOOLS_VERSION}/target/include
)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/json-3.3.0/single_include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/c-ares-${DRAIOS_CARES_VERSION}/target/include)

if(CYGWIN)
    include_directories("${WIN_HAL_INCLUDE}")
endif()

add_definitions(-DHAS_ANALYZER)
add_definitions(-DK8S_DISABLE_THREAD)

if(NOT CYGWIN)
    set(PROTOC
        LD_LIBRARY_PATH=${DRAIOS_DEPENDENCIES_DIR}/protobuf-${DRAIOS_PROTOBUF_VERSION}/target/lib
        ${DRAIOS_DEPENDENCIES_DIR}/protobuf-${DRAIOS_PROTOBUF_VERSION}/target/bin/protoc
    )

    add_custom_command(
        OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/cri.grpc.pb.cc ${CMAKE_CURRENT_BINARY_DIR}/cri.grpc.pb.h
               ${CMAKE_CURRENT_BINARY_DIR}/cri.pb.cc ${CMAKE_CURRENT_BINARY_DIR}/cri.pb.h
        COMMENT "Generate CRI grpc code"
        DEPENDS ${LIBSINSP_SOURCE_DIR}/cri.proto
        COMMAND ${PROTOC} -I ${LIBSINSP_SOURCE_DIR} --cpp_out=. ${LIBSINSP_SOURCE_DIR}/cri.proto
        COMMAND
            ${PROTOC} -I ${LIBSINSP_SOURCE_DIR} --grpc_out=.
            --plugin=protoc-gen-grpc=${DRAIOS_DEPENDENCIES_DIR}/grpc-${DRAIOS_GRPC_VERSION}/bins/opt/grpc_cpp_plugin
            ${LIBSINSP_SOURCE_DIR}/cri.proto
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    )

    add_custom_command(
        OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/container_events/containerd_container.grpc.pb.cc
               ${CMAKE_CURRENT_BINARY_DIR}/container_events/containerd_container.grpc.pb.h
               ${CMAKE_CURRENT_BINARY_DIR}/container_events/containerd_container.pb.cc
               ${CMAKE_CURRENT_BINARY_DIR}/container_events/containerd_container.pb.h
        COMMENT "Generate containerd events grpc code: container events"
        DEPENDS container_events/containerd_container.proto
        COMMAND mkdir -p container_events
        COMMAND ${PROTOC} -I ${CMAKE_CURRENT_SOURCE_DIR}/container_events --cpp_out=container_events
                ${CMAKE_CURRENT_SOURCE_DIR}/container_events/containerd_container.proto
        COMMAND
            ${PROTOC} -I ${CMAKE_CURRENT_SOURCE_DIR}/container_events --grpc_out=container_events
            --plugin=protoc-gen-grpc=${DRAIOS_DEPENDENCIES_DIR}/grpc-${DRAIOS_GRPC_VERSION}/bins/opt/grpc_cpp_plugin
            ${CMAKE_CURRENT_SOURCE_DIR}/container_events/containerd_container.proto
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    )

    add_custom_command(
        OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/container_events/containerd_events.grpc.pb.cc
               ${CMAKE_CURRENT_BINARY_DIR}/container_events/containerd_events.grpc.pb.h
               ${CMAKE_CURRENT_BINARY_DIR}/container_events/containerd_events.pb.cc
               ${CMAKE_CURRENT_BINARY_DIR}/container_events/containerd_events.pb.h
        COMMENT "Generate containerd events grpc code: event subscription"
        DEPENDS container_events/containerd_events.proto
        COMMAND mkdir -p container_events
        COMMAND ${PROTOC} -I ${CMAKE_CURRENT_SOURCE_DIR}/container_events --cpp_out=container_events
                ${CMAKE_CURRENT_SOURCE_DIR}/container_events/containerd_events.proto
        COMMAND
            ${PROTOC} -I ${CMAKE_CURRENT_SOURCE_DIR}/container_events --grpc_out=container_events
            --plugin=protoc-gen-grpc=${DRAIOS_DEPENDENCIES_DIR}/grpc-${DRAIOS_GRPC_VERSION}/bins/opt/grpc_cpp_plugin
            ${CMAKE_CURRENT_SOURCE_DIR}/container_events/containerd_events.proto
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    )

    add_custom_command(
        OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/container_events/containerd_image.grpc.pb.cc
               ${CMAKE_CURRENT_BINARY_DIR}/container_events/containerd_image.grpc.pb.h
               ${CMAKE_CURRENT_BINARY_DIR}/container_events/containerd_image.pb.cc
               ${CMAKE_CURRENT_BINARY_DIR}/container_events/containerd_image.pb.h
        COMMENT "Generate containerd events grpc code: image events"
        DEPENDS container_events/containerd_image.proto
        COMMAND mkdir -p container_events
        COMMAND ${PROTOC} -I ${CMAKE_CURRENT_SOURCE_DIR}/container_events --cpp_out=container_events
                ${CMAKE_CURRENT_SOURCE_DIR}/container_events/containerd_image.proto
        COMMAND
            ${PROTOC} -I ${CMAKE_CURRENT_SOURCE_DIR}/container_events --grpc_out=container_events
            --plugin=protoc-gen-grpc=${DRAIOS_DEPENDENCIES_DIR}/grpc-${DRAIOS_GRPC_VERSION}/bins/opt/grpc_cpp_plugin
            ${CMAKE_CURRENT_SOURCE_DIR}/container_events/containerd_image.proto
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    )

    add_custom_command(
        OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/container_events/containerd_mount.grpc.pb.cc
               ${CMAKE_CURRENT_BINARY_DIR}/container_events/containerd_mount.grpc.pb.h
               ${CMAKE_CURRENT_BINARY_DIR}/container_events/containerd_mount.pb.cc
               ${CMAKE_CURRENT_BINARY_DIR}/container_events/containerd_mount.pb.h
        COMMENT "Generate containerd events grpc code: mounts"
        DEPENDS container_events/containerd_mount.proto
        COMMAND mkdir -p container_events
        COMMAND ${PROTOC} -I ${CMAKE_CURRENT_SOURCE_DIR}/container_events --cpp_out=container_events
                ${CMAKE_CURRENT_SOURCE_DIR}/container_events/containerd_mount.proto
        COMMAND
            ${PROTOC} -I ${CMAKE_CURRENT_SOURCE_DIR}/container_events --grpc_out=container_events
            --plugin=protoc-gen-grpc=${DRAIOS_DEPENDENCIES_DIR}/grpc-${DRAIOS_GRPC_VERSION}/bins/opt/grpc_cpp_plugin
            ${CMAKE_CURRENT_SOURCE_DIR}/container_events/containerd_mount.proto
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    )

    add_custom_command(
        OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/container_events/containerd_task.grpc.pb.cc
               ${CMAKE_CURRENT_BINARY_DIR}/container_events/containerd_task.grpc.pb.h
               ${CMAKE_CURRENT_BINARY_DIR}/container_events/containerd_task.pb.cc
               ${CMAKE_CURRENT_BINARY_DIR}/container_events/containerd_task.pb.h
        COMMENT "Generate containerd events grpc code: task events"
        DEPENDS container_events/containerd_task.proto
        COMMAND mkdir -p container_events
        COMMAND ${PROTOC} -I ${CMAKE_CURRENT_SOURCE_DIR}/container_events --cpp_out=container_events
                ${CMAKE_CURRENT_SOURCE_DIR}/container_events/containerd_task.proto
        COMMAND
            ${PROTOC} -I ${CMAKE_CURRENT_SOURCE_DIR}/container_events --grpc_out=container_events
            --plugin=protoc-gen-grpc=${DRAIOS_DEPENDENCIES_DIR}/grpc-${DRAIOS_GRPC_VERSION}/bins/opt/grpc_cpp_plugin
            ${CMAKE_CURRENT_SOURCE_DIR}/container_events/containerd_task.proto
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    )

endif()

set(SANALYZER_SOURCES
    analyzer.cpp
    analyzer_fd.cpp
    analyzer_file_stat.cpp
    analyzer_parsers.cpp
    analyzer_thread.cpp
    analyzer_utils.cpp
    app_checks.cpp
    app_check_emitter.cpp
    audit_tap.cpp
    audit_tap_connection_aggregator.cpp
    audit_tap_connection_info.cpp
    audit_tap_network_connection.cpp
    secure_audit.cpp
    secure_helper.cpp
    secure_netsec.cpp
    secure_netsec_obj.cpp
    secure_netsec_cidr.cpp
    baseliner.cpp
    blake2/blake2b.c
    coclient.cpp
    cm_quantile.c
    connectinfo.cpp
    config.cpp
    container_config.cpp
    container_start_count.cpp
    container_events/docker.cpp
    cpu_profiler.cpp
    custom_container.cpp
    delays.cpp
    environment_emitter.cpp
    env_hash.cpp
    filter_limits.cpp
    heap.c
    infrastructure_state.cpp
    internal_metrics.cpp
    jmx_emitter.cpp
    jmx_proxy.cpp
    k8s_user_event_message_handler.cpp
    k8s_proto.cpp
    k8s_delegator.cpp
    k8s_limits.cpp
    label_limits.cpp
    memdumper.cpp
    memdump_logger.cpp
    mesos_proto.cpp
    metric_forwarding_configuration.cpp
    metric_limits.cpp
    metric_store.cpp
    metrics.cpp
    mount_points_limits.cpp
    mounted_fs.cpp
    null_statsd_emitter.cpp
    object_filter.cpp
    object_filter_config.cpp
    parser_http.cpp
    parser_mysql.cpp
    parser_postgres.cpp
    parser_mongodb.cpp
    parser_tls.cpp
    percentile.cpp
    proc_filter.cpp
    protocol_manager.cpp
    process_emitter.cpp
    proc_config.h
    process_manager.cpp
    procfs_parser.cpp
    procfs_scanner.cpp
    prometheus.cpp
    promscrape.cpp
    protostate.cpp
    security_config.cpp
    sched_analyzer.cpp
    scores.cpp
    sqlparser.cpp
    statsd_emitter.cpp
    statsd_emitter_factory.cpp
    statsd_metric.cpp
    statsd_server.cpp
    statsite_config.cpp
    statsite_proxy.cpp
    statsite_statsd_emitter.cpp
    statsite_forwarder.cpp
    transactinfo.cpp
    userdb.cpp
    k8s_namespace_store.cpp
    k8s_hpa_store.cpp
    k8s_pod_store.cpp
    k8s_object_store.cpp
    k8s_store_manager.cpp
    ${LIBSINSP_SOURCE_DIR}/addrinfo.cpp
    ${LIBSINSP_SOURCE_DIR}/cgroup_limits.cpp
    ${LIBSINSP_SOURCE_DIR}/chisel.cpp
    ${LIBSINSP_SOURCE_DIR}/chisel_api.cpp
    ${LIBSINSP_SOURCE_DIR}/cyclewriter.cpp
    ${LIBSINSP_SOURCE_DIR}/container.cpp
    ${LIBSINSP_SOURCE_DIR}/container_engine/container_engine_base.cpp
    ${LIBSINSP_SOURCE_DIR}/container_engine/docker_common.cpp
    ${LIBSINSP_SOURCE_DIR}/container_engine/static_container.cpp
    ${LIBSINSP_SOURCE_DIR}/container_info.cpp
    ${LIBSINSP_SOURCE_DIR}/dns_manager.cpp
    ${LIBSINSP_SOURCE_DIR}/dumper.cpp
    ${LIBSINSP_SOURCE_DIR}/event.cpp
    ${LIBSINSP_SOURCE_DIR}/eventformatter.cpp
    ${LIBSINSP_SOURCE_DIR}/fdinfo.cpp
    ${LIBSINSP_SOURCE_DIR}/filter.cpp
    ${LIBSINSP_SOURCE_DIR}/filterchecks.cpp
    ${LIBSINSP_SOURCE_DIR}/gen_filter.cpp
    ${LIBSINSP_SOURCE_DIR}/grpc_channel_registry.cpp
    ${LIBSINSP_SOURCE_DIR}/http_parser.c
    ${LIBSINSP_SOURCE_DIR}/http_reason.cpp
    ${LIBSINSP_SOURCE_DIR}/ifinfo.cpp
    ${LIBSINSP_SOURCE_DIR}/internal_metrics.cpp
    # ${LIBSINSP_SOURCE_DIR}/third-party/jsoncpp/jsoncpp.cpp
    k8s_config.cpp
    legacy_k8s_protobuf.cpp
    ${LIBSINSP_SOURCE_DIR}/logger.cpp
    ${LIBSINSP_SOURCE_DIR}/lua_parser.cpp
    ${LIBSINSP_SOURCE_DIR}/lua_parser_api.cpp
    ${LIBSINSP_SOURCE_DIR}/prefix_search.cpp
    ${LIBSINSP_SOURCE_DIR}/tracers.cpp
    ${LIBSINSP_SOURCE_DIR}/sinsp_auth.cpp
    ${LIBSINSP_SOURCE_DIR}/sinsp_curl.cpp
    ${LIBSINSP_SOURCE_DIR}/k8s.cpp
    ${LIBSINSP_SOURCE_DIR}/k8s_api_error.cpp
    ${LIBSINSP_SOURCE_DIR}/k8s_api_handler.cpp
    ${LIBSINSP_SOURCE_DIR}/k8s_component.cpp
    ${LIBSINSP_SOURCE_DIR}/k8s_daemonset_handler.cpp
    ${LIBSINSP_SOURCE_DIR}/k8s_deployment_handler.cpp
    ${LIBSINSP_SOURCE_DIR}/k8s_dispatcher.cpp
    ${LIBSINSP_SOURCE_DIR}/k8s_event_data.cpp
    ${LIBSINSP_SOURCE_DIR}/k8s_event_handler.cpp
    ${LIBSINSP_SOURCE_DIR}/k8s_handler.cpp
    ${LIBSINSP_SOURCE_DIR}/k8s_namespace_handler.cpp
    ${LIBSINSP_SOURCE_DIR}/k8s_net.cpp
    ${LIBSINSP_SOURCE_DIR}/k8s_node_handler.cpp
    ${LIBSINSP_SOURCE_DIR}/k8s_pod_handler.cpp
    ${LIBSINSP_SOURCE_DIR}/k8s_replicationcontroller_handler.cpp
    ${LIBSINSP_SOURCE_DIR}/k8s_replicaset_handler.cpp
    ${LIBSINSP_SOURCE_DIR}/k8s_service_handler.cpp
    ${LIBSINSP_SOURCE_DIR}/k8s_state.cpp
    ${LIBSINSP_SOURCE_DIR}/json_query.cpp
    ${LIBSINSP_SOURCE_DIR}/json_error_log.cpp
    ${LIBSINSP_SOURCE_DIR}/marathon_component.cpp
    ${LIBSINSP_SOURCE_DIR}/marathon_http.cpp
    ${LIBSINSP_SOURCE_DIR}/mesos_auth.cpp
    ${LIBSINSP_SOURCE_DIR}/mesos.cpp
    ${LIBSINSP_SOURCE_DIR}/mesos_collector.cpp
    ${LIBSINSP_SOURCE_DIR}/mesos_component.cpp
    ${LIBSINSP_SOURCE_DIR}/mesos_http.cpp
    ${LIBSINSP_SOURCE_DIR}/mesos_state.cpp
    ${LIBSINSP_SOURCE_DIR}/parsers.cpp
    ${LIBSINSP_SOURCE_DIR}/protodecoder.cpp
    ${LIBSINSP_SOURCE_DIR}/threadinfo.cpp
    ${LIBSINSP_SOURCE_DIR}/sinsp.cpp
    ${LIBSINSP_SOURCE_DIR}/stats.cpp
    ${LIBSINSP_SOURCE_DIR}/stopwatch.cpp
    ${LIBSINSP_SOURCE_DIR}/token_bucket.cpp
    ${LIBSINSP_SOURCE_DIR}/tracer_emitter.cpp
    ${LIBSINSP_SOURCE_DIR}/tuples.cpp
    ${LIBSINSP_SOURCE_DIR}/tuples.cpp
    ${LIBSINSP_SOURCE_DIR}/uri_parser.c
    ${LIBSINSP_SOURCE_DIR}/uri.cpp
    ${LIBSINSP_SOURCE_DIR}/user_event.cpp
    ${LIBSINSP_SOURCE_DIR}/user_event_logger.cpp
    ${LIBSINSP_SOURCE_DIR}/utils.cpp
    ${LIBSINSP_SOURCE_DIR}/value_parser.cpp
    ${LIBSINSP_SOURCE_DIR}/viewinfo.cpp
)

if(NOT CYGWIN)
    list(
        APPEND
        SANALYZER_SOURCES
        ${LIBSINSP_SOURCE_DIR}/cri.cpp
        ${LIBSINSP_SOURCE_DIR}/container_engine/bpm.cpp
        ${LIBSINSP_SOURCE_DIR}/container_engine/cri.cpp
        ${LIBSINSP_SOURCE_DIR}/container_engine/docker_linux.cpp
        ${LIBSINSP_SOURCE_DIR}/container_engine/libvirt_lxc.cpp
        ${LIBSINSP_SOURCE_DIR}/container_engine/lxc.cpp
        ${LIBSINSP_SOURCE_DIR}/container_engine/mesos.cpp
        ${LIBSINSP_SOURCE_DIR}/container_engine/rkt.cpp
        ${LIBSINSP_SOURCE_DIR}/runc.cpp
        container_events/containerd_container.grpc.pb.cc
        container_events/containerd_container.pb.cc
        container_events/containerd_events.grpc.pb.cc
        container_events/containerd_events.pb.cc
        container_events/containerd_image.grpc.pb.cc
        container_events/containerd_image.pb.cc
        container_events/containerd_mount.grpc.pb.cc
        container_events/containerd_mount.pb.cc
        container_events/containerd_task.grpc.pb.cc
        container_events/containerd_task.pb.cc
        container_events/containerd.cpp
        ${CMAKE_CURRENT_BINARY_DIR}/cri.grpc.pb.cc
        ${CMAKE_CURRENT_BINARY_DIR}/cri.pb.cc
    )
else()
    list(APPEND SANALYZER_SOURCES ${LIBSINSP_SOURCE_DIR}/container_engine/docker_win.cpp)
endif()

if(CYGWIN)
    set(POCO_LIB_DIR "bin")
    set(POCO_LIB_PREFIX "cyg")
else()
    set(POCO_LIB_DIR "lib")
    set(POCO_LIB_PREFIX "lib")
endif()

list(
    APPEND
    sanalyzer_common_link_libraries
    command-line
    userspace-shared
    scap
    draiosproto
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
    pthread
    ${DRAIOS_DEPENDENCIES_DIR}/yaml-${DRAIOS_YAML_VERSION}/target/lib/libyaml-cpp.a
)

if(ALPINE_BUILDER)
    list(APPEND sanalyzer_common_link_libraries execinfo)
else()
    list(APPEND sanalyzer_common_link_libraries anl)
endif()

list(APPEND sanalyzer_linux_link_libraries
     ${DRAIOS_DEPENDENCIES_DIR}/tbb-${DRAIOS_TBB_VERSION}/build/lib_release/libtbb.a
)

add_library(sanalyzer STATIC ${SANALYZER_SOURCES})
add_dependencies(sanalyzer draiosproto)

if(INCLUDE_INTERNAL_TEST_CODE)
    target_compile_definitions(sanalyzer PUBLIC SYSDIG_TEST)
endif()

if(GPERFTOOLS_AVAILABLE)
    # tcmalloc doesn't play well with valgrind/helgrind so we keep it out of the internal builds.
    list(
        APPEND
        sanalyzer_linux_link_libraries
        ${DRAIOS_DEPENDENCIES_DIR}/gperftools-${DRAIOS_GPERFTOOLS_VERSION}/target/lib/libtcmalloc_and_profiler.a
    )
endif()

if(NOT CYGWIN)
    target_link_libraries(
        sanalyzer ${sanalyzer_common_link_libraries} ${sanalyzer_linux_link_libraries}
    )
else()
    target_link_libraries(sanalyzer ${sanalyzer_common_link_libraries})
endif()
