include_directories(${DRAIOS_DEPENDENCIES_DIR}/poco-${DRAIOS_POCO_VERSION}/target/include)

add_library(test_helpers STATIC
	scoped_file_descriptor.cpp
	scoped_temp_file.cpp
)
