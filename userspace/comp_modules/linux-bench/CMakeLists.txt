install(
    PROGRAMS ${DRAIOS_DEPENDENCIES_DIR}/linux-bench-${DRAIOS_LINUX_BENCH_VERSION}/linux-bench
    DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/comp_modules/linux-bench
    COMPONENT agent-slim
)

install(
    DIRECTORY ${DRAIOS_DEPENDENCIES_DIR}/linux-bench-${DRAIOS_LINUX_BENCH_VERSION}/cfg
    DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/comp_modules/linux-bench
    COMPONENT agent-slim
)
