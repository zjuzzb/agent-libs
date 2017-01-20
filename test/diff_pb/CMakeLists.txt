include_directories(${DRAIOS_DEPENDENCIES_DIR}/protobuf-3.1.0/src)

add_executable(diff_pb
	metrics_list.pb.cc
	draios.pb.cc
	diff_pb.cpp)
	
target_link_libraries(diff_pb
	${DRAIOS_DEPENDENCIES_DIR}/protobuf-3.1.0/src/.libs/libprotobuf.a)

