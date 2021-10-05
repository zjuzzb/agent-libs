include_directories(${DRAIOS_DEPENDENCIES_DIR}/poco-${DRAIOS_POCO_VERSION}/target/include)

add_library(
    test_helpers STATIC
    http_server.cpp
    scoped_file_descriptor.cpp
    scoped_file_pointer.cpp
    scoped_fmemopen.cpp
    scoped_pipe.cpp
    scoped_stdout_capture.cpp
    scoped_temp_directory.cpp
    scoped_temp_file.cpp
)

target_link_libraries(
    test_helpers
    ${DRAIOS_DEPENDENCIES_DIR}/openssl-${DRAIOS_OPENSSL_VERSION}/target/lib/libssl.a
    ${DRAIOS_DEPENDENCIES_DIR}/openssl-${DRAIOS_OPENSSL_VERSION}/target/lib/libcrypto.a
    pthread
)
