find_package(JNI)
if(JNI_FOUND)
    include_directories(
        ${DRAIOS_DEPENDENCIES_DIR}/gtest-${DRAIOS_GTEST_VERSION}/include
        ${DRAIOS_DEPENDENCIES_DIR}/gtest-${DRAIOS_GTEST_VERSION}/fused-src/gtest
        ${PROJECT_SOURCE_DIR}/userspace/sdjagent/native
        ${JAVA_INCLUDE_PATH}
        ${JAVA_INCLUDE_PATH2}
        ${DRAIOS_DEPENDENCIES_DIR}/boost_${DRAIOS_BOOST_VERSION}
    )

    add_executable(unit-test-sdjagent-jni jni_test.cpp)

    target_link_libraries(
        unit-test-sdjagent-jni sdjagentjni_static ${JAVA_JVM_LIBRARY}
        ${DRAIOS_DEPENDENCIES_DIR}/gtest-${DRAIOS_GTEST_VERSION}/libgtest.a
    )

    install(
        TARGETS unit-test-sdjagent-jni
        DESTINATION ${CMAKE_INSTALL_PREFIX}/test/
        COMPONENT tests
    )
endif()
