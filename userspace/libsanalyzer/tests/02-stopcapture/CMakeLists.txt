include_directories(${PROJECT_SOURCE_DIR}/common)
include_directories(${PROJECT_SOURCE_DIR}/userspace/libscap)
include_directories(${PROJECT_SOURCE_DIR}/userspace/libsanalyzer/src)
include_directories(${LIBSCAP_INCLUDE_DIR})
include_directories(${LIBSINSP_INCLUDE_DIRS})
include_directories(${DRAIOS_DEPENDENCIES_DIR}/curl-${DRAIOS_CURL_VERSION}/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/tbb-${DRAIOS_TBB_VERSION}/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/json-3.3.0/single_include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/c-ares-${DRAIOS_CARES_VERSION}/target/include)

add_definitions(-DHAS_ANALYZER)

add_executable(sinsp-stopcapture test.cpp)

target_link_libraries(sinsp-stopcapture sanalyzer draiosproto test-helpers-libsanalyzer)

install(
    TARGETS sinsp-stopcapture
    DESTINATION ${CMAKE_INSTALL_PREFIX}/bin
    COMPONENT tests
)
