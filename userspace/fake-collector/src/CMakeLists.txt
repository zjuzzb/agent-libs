include_directories(${PROJECT_SOURCE_DIR}/userspace/dragent/src)
include_directories(${PROJECT_SOURCE_DIR}/userspace/libsanalyzer/src)
include_directories(${PROJECT_SOURCE_DIR}/userspace/userspace-shared/src)
include_directories(${PROJECT_BINARY_DIR}/userspace/draiosproto)
include_directories(${LIBSINSP_INCLUDE_DIRS})
include_directories(${DRAIOS_DEPENDENCIES_DIR}/poco-${DRAIOS_POCO_VERSION}/target/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/protobuf-${DRAIOS_PROTOBUF_VERSION}/target/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/zlib-${DRAIOS_ZLIB_VERSION})

add_library(fake-collector-core STATIC fake_collector.cpp $<TARGET_OBJECTS:appcommonl>)
target_link_libraries(
    fake-collector-core
    draiosproto
    ${DRAIOS_DEPENDENCIES_DIR}/openssl-${DRAIOS_OPENSSL_VERSION}/target/lib/libssl.a
    ${DRAIOS_DEPENDENCIES_DIR}/openssl-${DRAIOS_OPENSSL_VERSION}/target/lib/libcrypto.a
    pthread
)

add_executable(fake-collector main.cpp)

target_link_libraries(
    fake-collector
    draiosproto
    sanalyzer
    dragentl
    fake-collector-core
)

install(
    TARGETS fake-collector
    DESTINATION ${CMAKE_INSTALL_PREFIX}/test/
    COMPONENT fake-collector
)
