include_directories(${DRAIOS_DEPENDENCIES_DIR}/poco-${DRAIOS_POCO_VERSION}/target/include)

add_library(test-helpers-librest STATIC
	dummy_server_request.cpp
	dummy_server_response.cpp
)

target_compile_definitions(test-helpers-librest PUBLIC SYSDIG_TEST)


