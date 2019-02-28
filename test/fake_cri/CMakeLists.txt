include_directories(${DRAIOS_DEPENDENCIES_DIR}/grpc-${DRAIOS_GRPC_VERSION}/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/protobuf-${DRAIOS_PROTOBUF_VERSION}/target/include)
include_directories(${CMAKE_CURRENT_BINARY_DIR})

set(PROTOC LD_LIBRARY_PATH=${DRAIOS_DEPENDENCIES_DIR}/protobuf-${DRAIOS_PROTOBUF_VERSION}/target/lib
        ${DRAIOS_DEPENDENCIES_DIR}/protobuf-${DRAIOS_PROTOBUF_VERSION}/target/bin/protoc)

add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/cri.grpc.pb.cc
        ${CMAKE_CURRENT_BINARY_DIR}/cri.grpc.pb.h
        ${CMAKE_CURRENT_BINARY_DIR}/cri.pb.cc
        ${CMAKE_CURRENT_BINARY_DIR}/cri.pb.h
        COMMENT "Generate CRI grpc code"
        DEPENDS ${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/cri.proto
        COMMAND ${PROTOC} -I ${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp --cpp_out=. ${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/cri.proto
        COMMAND ${PROTOC} -I ${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp --grpc_out=. --plugin=protoc-gen-grpc=${DRAIOS_DEPENDENCIES_DIR}/grpc-1.8.1/bins/opt/grpc_cpp_plugin ${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/cri.proto
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

add_executable(fake_cri
        fake_cri.cpp
        ${CMAKE_CURRENT_BINARY_DIR}/cri.grpc.pb.cc
        ${CMAKE_CURRENT_BINARY_DIR}/cri.pb.cc
        )

target_link_libraries(fake_cri
        ${DRAIOS_DEPENDENCIES_DIR}/grpc-1.8.1/libs/opt/libgrpc++_unsecure.a
        ${DRAIOS_DEPENDENCIES_DIR}/grpc-1.8.1/libs/opt/libgrpc_unsecure.a
        ${DRAIOS_DEPENDENCIES_DIR}/c-ares-${DRAIOS_CARES_VERSION}/target/lib/libcares.a
        ${DRAIOS_DEPENDENCIES_DIR}/protobuf-${DRAIOS_PROTOBUF_VERSION}/target/lib/libprotobuf.a
        pthread
        rt)

install(TARGETS fake_cri
        DESTINATION ${CMAKE_INSTALL_PREFIX}/test/resources
        COMPONENT tests)

install(FILES
        fake_cri_agent_container.pb
        fake_cri_agent_pod.pb
        fake_cri_crio_container.pb
        fake_cri_crio_pod.pb
        fake_cri_crio_images.pb
        DESTINATION ${CMAKE_INSTALL_PREFIX}/test/resources
        COMPONENT tests)