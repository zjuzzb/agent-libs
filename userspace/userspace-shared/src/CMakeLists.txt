include_directories(${LIBSINSP_INCLUDE_DIRS})
include_directories(${DRAIOS_DEPENDENCIES_DIR}/poco-${DRAIOS_POCO_VERSION}/target/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/yaml-${DRAIOS_YAML_VERSION}/target/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/boost_${DRAIOS_BOOST_VERSION})
include_directories(${CMAKE_CURRENT_BINARY_DIR}/../../draiosproto)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/protobuf-${DRAIOS_PROTOBUF_VERSION}/target/include)

add_library(
    userspace-shared STATIC
    configuration_manager.cpp
    configuration_unit.cpp
    common_logger.cpp
    fault_handler.cpp
    fault_handler_registry.cpp
    feature_manager.cpp
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

if(INCLUDE_INTERNAL_TEST_CODE)
    target_compile_definitions(userspace-shared PUBLIC SYSDIG_TEST)
endif()
