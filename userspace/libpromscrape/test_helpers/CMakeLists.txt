include_directories(${CMAKE_CURRENT_BINARY_DIR})
include_directories(${DRAIOS_DEPENDENCIES_DIR}/grpc-${DRAIOS_GRPC_VERSION}/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/protobuf-${DRAIOS_PROTOBUF_VERSION}/target/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/poco-${DRAIOS_POCO_VERSION}/target/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/yaml-${DRAIOS_YAML_VERSION}/target/include)
include_directories(${PROJECT_SOURCE_DIR}/userspace/libpromscrape/src)
include_directories(${PROJECT_SOURCE_DIR}/userspace/userspace-shared/src)
include_directories(${CMAKE_CURRENT_BINARY_DIR}/../../draiosproto)

add_library(
    test-helpers-libpromscrape STATIC
    prom_factory_helper.cpp
    prom_scrape_helper.cpp
)

add_dependencies(test-helpers-libpromscrape draiosproto)

target_compile_definitions(test-helpers-libpromscrape PUBLIC SYSDIG_TEST)
