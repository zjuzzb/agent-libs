include_directories(${LIBSCAP_INCLUDE_DIR})
include_directories(${LIBSINSP_INCLUDE_DIRS})
include_directories(${PROJECT_SOURCE_DIR}/userspace/libsanalyzer/src)
include_directories(${PROJECT_SOURCE_DIR}/userspace/userspace-shared/src)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/boost_${DRAIOS_BOOST_VERSION})
include_directories(${DRAIOS_DEPENDENCIES_DIR}/curl-${DRAIOS_CURL_VERSION}/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/grpc-${DRAIOS_GRPC_VERSION}/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/jq-${DRAIOS_JQ_VERSION})
include_directories(${DRAIOS_DEPENDENCIES_DIR}/libb64-${DRAIOS_B64_VERSION}/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/openssl-${DRAIOS_OPENSSL_VERSION}/target/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/poco-${DRAIOS_POCO_VERSION}/target/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/protobuf-${DRAIOS_PROTOBUF_VERSION}/target/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/yaml-${DRAIOS_YAML_VERSION}/target/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/tbb-${DRAIOS_TBB_VERSION}/include)
include_directories(${CMAKE_CURRENT_BINARY_DIR}/../../../draiosproto)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/json-3.3.0/single_include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/c-ares-${DRAIOS_CARES_VERSION}/target/include)

add_definitions(-DHAS_ANALYZER)

add_executable(sinsp-open test.cpp)

target_link_libraries(sinsp-open sanalyzer draiosproto pthread)

if(CYGWIN)
    target_link_libraries(sinsp-open /lib/w32api/libiphlpapi.a)
endif()

install(
    TARGETS sinsp-open
    DESTINATION ${CMAKE_INSTALL_PREFIX}/bin
    COMPONENT tests
)
