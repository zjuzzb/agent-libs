include_directories(${DRAIOS_DEPENDENCIES_DIR}/grpc-${DRAIOS_GRPC_VERSION}/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/poco-${DRAIOS_POCO_VERSION}/target/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/yaml-${DRAIOS_YAML_VERSION}/target/include)
include_directories(${CMAKE_CURRENT_BINARY_DIR}/../../draiosproto)
include_directories(${PROJECT_SOURCE_DIR}/userspace/userspace-shared/src)
include_directories(${PROJECT_SOURCE_DIR}/userspace/command-line/src)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/protobuf-${DRAIOS_PROTOBUF_VERSION}/target/include)

add_library(
    promscrape STATIC
    promscrape.cpp
    promscrape_cli.cpp
    promscrape_conf.cpp
    ${LIBSINSP_SOURCE_DIR}/third-party/jsoncpp/jsoncpp.cpp
)

set(POCO_LIB_DIR "lib")
set(POCO_LIB_PREFIX "lib")

list(
    APPEND
    promscrape_link_libraries
    command-line
    userspace-shared
    draiosproto
    ${DRAIOS_DEPENDENCIES_DIR}/poco-${DRAIOS_POCO_VERSION}/target/${POCO_LIB_DIR}/${POCO_LIB_PREFIX}PocoNet.a
    ${DRAIOS_DEPENDENCIES_DIR}/poco-${DRAIOS_POCO_VERSION}/target/${POCO_LIB_DIR}/${POCO_LIB_PREFIX}PocoFoundation.a
)

add_dependencies(promscrape userspace-shared draiosproto)
target_link_libraries(promscrape ${promscrape_link_libraries})
