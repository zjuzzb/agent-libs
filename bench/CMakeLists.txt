add_executable(bench
    bench.cpp
)

include_directories(${DRAIOS_DEPENDENCIES_DIR}/benchmark/include)

target_link_libraries(bench
    ${DRAIOS_DEPENDENCIES_DIR}/benchmark/build/src/libbenchmark.a
    ${DRAIOS_DEPENDENCIES_DIR}/benchmark/build/src/libbenchmark_main.a
    rt
)

install(TARGETS bench
    DESTINATION ${CMAKE_INSTALL_PREFIX}/test/
    COMPONENT tests)
