include_directories(${DRAIOS_DEPENDENCIES_DIR}/poco-${DRAIOS_POCO_VERSION}/target/include)

add_library(test_helpers STATIC
	scoped_file_descriptor.cpp
	scoped_file_pointer.cpp
	scoped_pipe.cpp
	scoped_stdout_capture.cpp
	scoped_temp_directory.cpp
	scoped_temp_file.cpp
)
