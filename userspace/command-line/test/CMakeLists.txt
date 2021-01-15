include_directories(${PROJECT_SOURCE_DIR}/userspace/command-line/src)
include_directories(${PROJECT_SOURCE_DIR}/userspace/userspace-shared/src)
include_directories(${PROJECT_SOURCE_DIR}/userspace/userspace-shared/test-helpers)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/boost_${DRAIOS_BOOST_VERSION})
include_directories(${DRAIOS_DEPENDENCIES_DIR}/gtest-${DRAIOS_GTEST_VERSION}/fused-src/gtest)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/poco-${DRAIOS_POCO_VERSION}/target/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/yaml-${DRAIOS_YAML_VERSION}/target/include)

add_executable(
    unit-test-command-line
    main.cpp
    command_line_permissions.ut.cpp
    command_line_manager.ut.cpp
    command_line_runnable.ut.cpp
)

target_link_libraries(
    unit-test-command-line
    command-line
    rt
    userspace-shared
    test-helpers-userspace-shared
    ${DRAIOS_DEPENDENCIES_DIR}/poco-${DRAIOS_POCO_VERSION}/target/lib/libPocoFoundation.a
    ${DRAIOS_DEPENDENCIES_DIR}/gtest-${DRAIOS_GTEST_VERSION}/libgtest.a
    pthread
    ${DRAIOS_DEPENDENCIES_DIR}/yaml-${DRAIOS_YAML_VERSION}/target/lib/libyaml-cpp.a
)

if(RUN_UNIT_TEST_UNDER_CODE_COVERAGE)
    add_custom_target(
        run-unit-test-command-line
        DEPENDS unit-test-command-line
        COMMAND ${PROJECT_SOURCE_DIR}/scripts/code-coverage lcov ./unit-test-command-line
                command-line.lcov
    )
else()
    add_custom_target(
        run-unit-test-command-line
        DEPENDS unit-test-command-line
        COMMAND unit-test-command-line
    )
endif()

if(CMAKE_BUILD_TYPE STREQUAL "DebugInternal")
    # We should add helgrind to this
    add_custom_target(
        valgrind-unit-test-command-line
        DEPENDS unit-test-command-line
        COMMAND valgrind --error-exitcode=1 --gen-suppressions=all
                --soname-synonyms=somalloc=tcmalloc ./unit-test-command-line
    )
else()
    add_custom_target(
        valgrind-unit-test-command-line
        COMMAND
            echo
            "Error: Valgrind not supported in this build variant. Use the debug-internal build instead."
            && false
    )
endif()

install(
    TARGETS unit-test-command-line
    DESTINATION ${CMAKE_INSTALL_PREFIX}/test/
    COMPONENT unit-test-command-line
)
