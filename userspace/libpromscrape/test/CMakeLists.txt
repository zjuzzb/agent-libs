include_directories(${PROJECT_SOURCE_DIR}/userspace/command-line/src)
include_directories(${PROJECT_SOURCE_DIR}/userspace/libpromscrape/src)
include_directories(${PROJECT_SOURCE_DIR}/userspace/userspace-shared/src)
include_directories(${PROJECT_SOURCE_DIR}/userspace/libpromscrape/test_helpers)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/gtest-${DRAIOS_GTEST_VERSION}/fused-src/gtest)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/poco-${DRAIOS_POCO_VERSION}/target/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/yaml-${DRAIOS_YAML_VERSION}/target/include)
include_directories(${CMAKE_CURRENT_BINARY_DIR}/../../draiosproto)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/protobuf-${DRAIOS_PROTOBUF_VERSION}/target/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/grpc-${DRAIOS_GRPC_VERSION}/include)

add_executable(
    unit-test-promscrape
    main.cpp
    prom_job.ut.cpp
    prom_v1.ut.cpp
    prom_v2.ut.cpp
    prom_job_metadata.ut.cpp
    prom_metadata_scraper.ut.cpp 
    promscrape.ut.cpp
    promscrape_cli.ut.cpp
)

target_link_libraries(
    unit-test-promscrape
    command-line
    promscrape
    userspace-shared
    draiosproto
    test-helpers-libpromscrape
    ${DRAIOS_DEPENDENCIES_DIR}/poco-${DRAIOS_POCO_VERSION}/target/lib/libPocoFoundation.a
    ${DRAIOS_DEPENDENCIES_DIR}/gtest-${DRAIOS_GTEST_VERSION}/libgtest.a
    ${DRAIOS_DEPENDENCIES_DIR}/yaml-${DRAIOS_YAML_VERSION}/target/lib/libyaml-cpp.a
    rt
)

if(RUN_UNIT_TEST_UNDER_CODE_COVERAGE)
    add_custom_target(
        run-unit-test-promscrape
        DEPENDS unit-test-promscrape
        COMMAND ${PROJECT_SOURCE_DIR}/scripts/code-coverage lcov ./unit-test-promscrape
                promscrape.lcov
    )
else()
    add_custom_target(
        run-unit-test-promscrape
        DEPENDS unit-test-promscrape
        COMMAND unit-test-promscrape
    )
endif()

if(CMAKE_BUILD_TYPE STREQUAL "DebugInternal")
    # We should add helgrind to this
    add_custom_target(
        valgrind-unit-test-promscrape
        DEPENDS unit-test-promscrape
        COMMAND valgrind --error-exitcode=1 --gen-suppressions=all
                --soname-synonyms=somalloc=tcmalloc ./unit-test-promscrape
    )
else()
    add_custom_target(
        valgrind-unit-test-promscrape
        COMMAND
            echo
            "Error: Valgrind not supported in this build variant. Use the debug-internal build instead."
            && false
    )
endif()

install(
    TARGETS unit-test-promscrape
    DESTINATION ${CMAKE_INSTALL_PREFIX}/test/
    COMPONENT unit-test-promscrape
)
