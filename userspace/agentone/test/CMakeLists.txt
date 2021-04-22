include_directories(${PROJECT_SOURCE_DIR}/userspace/agentone/src)
include_directories(${PROJECT_SOURCE_DIR}/userspace/agentone/test)
include_directories(${PROJECT_SOURCE_DIR}/userspace/test_helpers/src)
include_directories(${PROJECT_SOURCE_DIR}/userspace/userspace-shared/test-helpers)
include_directories(${PROJECT_SOURCE_DIR}/userspace/dragent/test_helpers)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/gtest-${DRAIOS_GTEST_VERSION}/fused-src/gtest)
include_directories(${CMAKE_CURRENT_BINARY_DIR}/../../draiosproto)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/protobuf-${DRAIOS_PROTOBUF_VERSION}/target/include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../../dragent/src)
include_directories(${PROJECT_SOURCE_DIR}/userspace/agentone/test/fake_agentino)
# The following includes are necessary because connection_manager pulls in the world just to get the
# message_handler definition
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../../userspace-shared/src)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../../libsanalyzer/src)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/poco-${DRAIOS_POCO_VERSION}/target/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/yaml-${DRAIOS_YAML_VERSION}/target/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/boost_${DRAIOS_BOOST_VERSION})
include_directories(${DRAIOS_DEPENDENCIES_DIR}/grpc-${DRAIOS_GRPC_VERSION}/include)

add_executable(unit-test-agentone
               main.cpp
               container_manager.ut.cpp
               agentino_manager.ut.cpp
               thread_pool.ut.cpp)

target_link_libraries(
    unit-test-agentone
    agentonel
    fake-agentino
    userspace-shared
    dragentl
    ${DRAIOS_DEPENDENCIES_DIR}/gtest-${DRAIOS_GTEST_VERSION}/libgtest.a
    pthread
    draiosproto
)

if(RUN_UNIT_TEST_UNDER_CODE_COVERAGE)
    add_custom_target(
        run-unit-test-agentone
        DEPENDS unit-test-agentone
        COMMAND ${PROJECT_SOURCE_DIR}/scripts/code-coverage lcov ./unit-test-agentone agentone.lcov
    )
else()
    add_custom_target(
        run-unit-test-agentone
        DEPENDS unit-test-agentone
        COMMAND unit-test-agentone
    )
endif()

if(CMAKE_BUILD_TYPE STREQUAL "DebugInternal")
    # We should add helgrind to this
    add_custom_target(
        valgrind-unit-test-agentone
        DEPENDS unit-test-agentone
        COMMAND valgrind --error-exitcode=1 --gen-suppressions=all
                --soname-synonyms=somalloc=tcmalloc ./unit-test-agentone
    )
else()
    add_custom_target(
        valgrind-unit-test-agentone
        COMMAND
            echo
            "Error: Valgrind not supported in this build variant. Use the debug-internal build instead."
            && false
    )
endif()

install(
    TARGETS unit-test-agentone
    DESTINATION ${CMAKE_INSTALL_PREFIX}/test/
    COMPONENT unit-test-agentone
)
