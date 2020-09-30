include_directories(${CMAKE_CURRENT_BINARY_DIR})
include_directories(${DRAIOS_DEPENDENCIES_DIR}/gtest-${DRAIOS_GTEST_VERSION}/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/protobuf-${DRAIOS_PROTOBUF_VERSION}/target/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/zlib-${DRAIOS_ZLIB_VERSION})
include_directories(${PROJECT_SOURCE_DIR}/../sysdig/userspace)
include_directories(${PROJECT_SOURCE_DIR}/../sysdig/userspace/async)
include_directories(${PROJECT_SOURCE_DIR}/../sysdig/userspace/libscap)
include_directories(${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp)
include_directories(${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/third-party/jsoncpp)
include_directories(${PROJECT_SOURCE_DIR}/userspace/draiosproto)
include_directories(${PROJECT_SOURCE_DIR}/userspace/librest/src)
include_directories(${PROJECT_SOURCE_DIR}/userspace/libsanalyzer/src)
include_directories(${PROJECT_SOURCE_DIR}/userspace/userspace-shared/src)
include_directories(${CMAKE_CURRENT_BINARY_DIR}/../../draiosproto)
include_directories(${PROJECT_SOURCE_DIR}/../oss-falco/userspace/engine)
include_directories(${PROJECT_BINARY_DIR}/userspace/engine)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/openssl-${DRAIOS_OPENSSL_VERSION}/target/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/poco-${DRAIOS_POCO_VERSION}/target/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/yaml-${DRAIOS_YAML_VERSION}/target/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/boost_${DRAIOS_BOOST_VERSION})
include_directories(${DRAIOS_DEPENDENCIES_DIR}/curl-${DRAIOS_CURL_VERSION}/include)
include_directories(
    ${DRAIOS_DEPENDENCIES_DIR}/gperftools-${DRAIOS_GPERFTOOLS_VERSION}/target/include
)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/libb64-${DRAIOS_B64_VERSION}/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/jq-${DRAIOS_JQ_VERSION})
include_directories(${DRAIOS_DEPENDENCIES_DIR}/grpc-${DRAIOS_GRPC_VERSION}/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/tbb-${DRAIOS_TBB_VERSION}/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/c-ares-${DRAIOS_CARES_VERSION}/target/include)

add_definitions(-DHAS_ANALYZER)

list(
    APPEND
    targetfiles
    app_checks_proxy.cpp
    async_aggregator.cpp
    avoid_block_channel.cpp
    baseline_mgr.cpp
    capture_job_handler.cpp
    cm_proxy_tunnel.cpp
    cm_socket.cpp
    compliance_mgr.cpp
    configlist_rest_request_handler.cpp
    configuration.cpp
    config_data_message_handler.cpp
    config_data_rest_request_handler.cpp
    config_rest_request_handler.cpp
    config_update.cpp
    container_size_requestor.cpp
    connection_manager.cpp
    crash_handler.cpp
    dragent_memdump_logger.cpp
    dragent_user_event_callback.cpp
    dump_request_start_message_handler.cpp
    dump_request_stop_message_handler.cpp
    error_handler.cpp
    faultlist_rest_request_handler.cpp
    fault_rest_request_handler.cpp
    file_emitter.cpp
    file_rest_registry.cpp
    file_rest_request_handler.cpp
    globally_readable_file_channel.cpp
    metric_serializer.cpp
    metrics_file_emitter.cpp
    pre_aggregated_metrics_rest_request_handler.cpp
    protobuf_file_emitter.cpp
    post_aggregated_metrics_rest_request_handler.cpp
    metrics_rest_request_helper.cpp
    monitor.cpp
    null_message_handler.cpp
    protocol.cpp
    running_state.cpp
    security_action.cpp
    security_compliance_calendar_message_handler.cpp
    security_compliance_run_message_handler.cpp
    security_mgr.cpp
    security_orchestrator_events_message_handler.cpp
    security_policy.cpp
    protobuf_metric_serializer.cpp
    protocol_handler.cpp
    security_policies_message_handler.cpp
    security_policies_v2_message_handler.cpp
    security_rule.cpp
    sinsp_factory.cpp
    sinsp_worker.cpp
    subprocesses_logger.cpp
    user_event_channel.cpp
    webpage.cpp
    webpage_rest_request_handler.cpp
    Poco/SysdigModifiedFileChannel.cpp
)

list(APPEND dragentfiles dragent.cpp)

list(APPEND agentonefiles agentone.cpp)

if(CYGWIN)
    # windows specific implementation
    list(APPEND targetfiles windows_helpers.cpp windows/process_helpers.cpp)
else()
    # linux specific implementation
    list(APPEND targetfiles linux/process_helpers.cpp)
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
    dragent_link_libraries
    ${DRAIOS_DEPENDENCIES_DIR}/libb64-${DRAIOS_B64_VERSION}/src/libb64.a
    ${DRAIOS_DEPENDENCIES_DIR}/poco-${DRAIOS_POCO_VERSION}/target/${POCO_LIB_DIR}/${POCO_LIB_PREFIX}PocoNetSSL.a
    ${DRAIOS_DEPENDENCIES_DIR}/poco-${DRAIOS_POCO_VERSION}/target/${POCO_LIB_DIR}/${POCO_LIB_PREFIX}PocoUtil.a
    ${DRAIOS_DEPENDENCIES_DIR}/poco-${DRAIOS_POCO_VERSION}/target/${POCO_LIB_DIR}/${POCO_LIB_PREFIX}PocoNet.a
    ${DRAIOS_DEPENDENCIES_DIR}/poco-${DRAIOS_POCO_VERSION}/target/${POCO_LIB_DIR}/${POCO_LIB_PREFIX}PocoFoundation.a
    rt
    ${DRAIOS_DEPENDENCIES_DIR}/yaml-${DRAIOS_YAML_VERSION}/target/lib/libyaml-cpp.a
)

# These libraries cause issues if included in UTs, so we have to link them outside
# of the libraries, and only link them into the actual application.
if(NOT CYGWIN)
    list(
        APPEND
        dragent_application_link_libraries
        ${DRAIOS_DEPENDENCIES_DIR}/openssl-${DRAIOS_OPENSSL_VERSION}/target/lib/libssl.a
        ${DRAIOS_DEPENDENCIES_DIR}/openssl-${DRAIOS_OPENSSL_VERSION}/target/lib/libcrypto.a
        ${DRAIOS_DEPENDENCIES_DIR}/gperftools-${DRAIOS_GPERFTOOLS_VERSION}/target/lib/libtcmalloc_and_profiler.a
    )
else()
    list(APPEND
        dragent_application_link_libraries
         ${DRAIOS_DEPENDENCIES_DIR}/openssl-${DRAIOS_OPENSSL_VERSION}/target/lib/libcrypto.a
         /lib/w32api/libiphlpapi.a
    )
endif()

add_library(dragentl STATIC ${targetfiles} ${dragentfiles})
target_link_libraries(dragentl falco_engine ${dragent_link_libraries})

add_library(agentonel STATIC ${targetfiles} ${agentonefiles})
target_link_libraries(agentonel falco_engine ${dragent_link_libraries})

if(INCLUDE_INTERNAL_TEST_CODE)
    target_compile_definitions(dragentl PUBLIC SYSDIG_TEST)
endif()

add_executable(dragent agent_main.cpp)
add_executable(agentone agentone_main.cpp)

target_link_libraries(
    dragent
    pthread
    sanalyzer
    dragentl
    draiosproto
    librestl
    ${dragent_application_link_libraries}
)
target_link_libraries(
    agentone
    pthread
    sanalyzer
    agentonel
    draiosproto
    librestl
    ${dragent_application_link_libraries}
)

file(COPY ${PROJECT_SOURCE_DIR}/scripts/rpm/dragent.in
     DESTINATION ${PROJECT_BINARY_DIR}/scripts/rpm
)

file(COPY root.cert DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

file(COPY chisels DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

file(COPY ${PROJECT_SOURCE_DIR}/../sysdig/userspace/sysdig/chisels/common.lua
          ${PROJECT_SOURCE_DIR}/../sysdig/userspace/sysdig/chisels/dkjson.lua
     DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/chisels
)

if(DEFINED AGENT_BUILD_COMMIT OR DEFINED AGENT_BUILD_DATE)
    if(DEFINED AGENT_BUILD_COMMIT)
        file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/.agent_build "commit: ${AGENT_BUILD_COMMIT}\n")
    endif()
    if(DEFINED AGENT_BUILD_DATE)
        file(APPEND ${CMAKE_CURRENT_BINARY_DIR}/.agent_build "build date: ${AGENT_BUILD_DATE}\n")
    endif()
    install(
        FILES ${CMAKE_CURRENT_BINARY_DIR}/.agent_build
        DESTINATION ${CMAKE_INSTALL_PREFIX}/etc
        COMPONENT agent-slim
    )
endif()

install(
    TARGETS dragent
    DESTINATION ${CMAKE_INSTALL_PREFIX}/bin
    COMPONENT agent-slim
)

install(
    TARGETS agentone
    DESTINATION ${CMAKE_INSTALL_PREFIX}/bin
    COMPONENT agentone
)

install(
    FILES root.cert
    DESTINATION ${CMAKE_INSTALL_PREFIX}
    COMPONENT agent-slim
)

install(
    FILES dragent.default.yaml
    DESTINATION ${CMAKE_INSTALL_PREFIX}/etc
    COMPONENT agent-slim
)

install(
    FILES prometheus-v2.default.yaml
    DESTINATION ${CMAKE_INSTALL_PREFIX}/etc
    COMPONENT agent-slim
)

install(
    FILES root.cert
    DESTINATION ${CMAKE_INSTALL_PREFIX}
    COMPONENT agentone
)

install(
    FILES dragent.default.yaml
    DESTINATION ${CMAKE_INSTALL_PREFIX}/etc
    COMPONENT agentone
)

install(
    FILES prometheus-v2.default.yaml
    DESTINATION ${CMAKE_INSTALL_PREFIX}/etc
    COMPONENT agentone
)

install(
    DIRECTORY chisels
    DESTINATION ${CMAKE_INSTALL_PREFIX}/share
    COMPONENT agent-slim
)

install(
    FILES ${PROJECT_SOURCE_DIR}/../sysdig/userspace/sysdig/chisels/common.lua
          ${PROJECT_SOURCE_DIR}/../sysdig/userspace/sysdig/chisels/dkjson.lua
    DESTINATION ${CMAKE_INSTALL_PREFIX}/share/chisels
    COMPONENT agent-slim
)

if(CYGWIN)
    install(
        FILES ${DRAGENT_WINHAL_DIR}/target/bin/dragent_win_hal.dll
        PERMISSIONS OWNER_EXECUTE OWNER_READ
        DESTINATION ${CMAKE_INSTALL_PREFIX}/bin
        COMPONENT agent-slim
    )

    install(
        FILES /bin/cygstdc++-6.dll
        PERMISSIONS OWNER_EXECUTE OWNER_READ
        DESTINATION ${CMAKE_INSTALL_PREFIX}/bin
        COMPONENT agent-slim
    )

    install(
        FILES /bin/cyggcc_s-seh-1.dll
        PERMISSIONS OWNER_EXECUTE OWNER_READ
        DESTINATION ${CMAKE_INSTALL_PREFIX}/bin
        COMPONENT agent-slim
    )

    install(
        FILES /bin/cygwin1.dll
        PERMISSIONS OWNER_EXECUTE OWNER_READ
        DESTINATION ${CMAKE_INSTALL_PREFIX}/bin
        COMPONENT agent-slim
    )

    install(
        FILES ${DRAGENT_WINHAL_DIR}/target/bin/DragentService.exe
        PERMISSIONS OWNER_EXECUTE OWNER_READ
        DESTINATION ${CMAKE_INSTALL_PREFIX}
        COMPONENT agent-slim
    )

    install(
        FILES ${PROJECT_SOURCE_DIR}/windows/wix_installer/dragent.wxs
        DESTINATION ${CMAKE_INSTALL_PREFIX}
        COMPONENT agent-slim
    )

    install(
        FILES ${PROJECT_SOURCE_DIR}/windows/wix_installer/make_msi.sh
        PERMISSIONS OWNER_EXECUTE OWNER_READ
        DESTINATION ${CMAKE_INSTALL_PREFIX}
        COMPONENT agent-slim
    )
endif()

configure_file(agent-config.h.in agent-config.h)
