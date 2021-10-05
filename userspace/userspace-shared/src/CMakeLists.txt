include_directories(${LIBSINSP_INCLUDE_DIRS})
include_directories(${DRAIOS_DEPENDENCIES_DIR}/openssl-${DRAIOS_OPENSSL_VERSION}/target/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/curl-${DRAIOS_CURL_VERSION}/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/grpc-${DRAIOS_GRPC_VERSION}/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/poco-${DRAIOS_POCO_VERSION}/target/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/yaml-${DRAIOS_YAML_VERSION}/target/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/boost_${DRAIOS_BOOST_VERSION})
include_directories(${CMAKE_CURRENT_BINARY_DIR}/../../draiosproto)
include_directories(${PROJECT_SOURCE_DIR}/userspace/userspace-shared/src)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/protobuf-${DRAIOS_PROTOBUF_VERSION}/target/include)

add_library(
    userspace-shared STATIC
    configuration_manager.cpp
    configuration_unit.cpp
    common_logger.cpp
    fault_handler.cpp
    fault_handler_registry.cpp
    feature_manager.cpp
    limits/metric_limits.cpp
    limits/filter_limits.cpp
    limits/metric_forwarding_configuration.cpp
    network_utils.cpp
    posix_queue.cpp
    string_utils.cpp
    thread_utils.cpp
    uptime.cpp
    wall_time.cpp
    watchdog_runnable_pool.cpp
    watchdog_runnable.cpp
    ${LIBSINSP_SOURCE_DIR}/third-party/jsoncpp/jsoncpp.cpp
)

add_dependencies(userspace-shared draiosproto)
target_link_libraries(userspace-shared draiosproto)

if(INCLUDE_INTERNAL_TEST_CODE)
    target_compile_definitions(userspace-shared PUBLIC SYSDIG_TEST)
endif()


add_library(ssl_shim OBJECT ssl_shim.cpp)
