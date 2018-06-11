include_directories(${DRAIOS_DEPENDENCIES_DIR}/protobuf-3.5.0/src)
include_directories(${CMAKE_BINARY_DIR}/userspace/draiosproto)

add_executable(diff_pb
	metrics_list.pb.cc
	diff_pb.cpp)
	
target_link_libraries(diff_pb
	draiosproto)

install(TARGETS diff_pb
        DESTINATION ${CMAKE_INSTALL_PREFIX}/test/
        COMPONENT tests)
