find_package(Java 1.6 COMPONENTS Development)
find_package(JNI)

if(Java_Development_FOUND)
    add_custom_target(sdjagent ALL COMMAND JAVA_HOME=${JAVA_HOME} ${DRAIOS_DEPENDENCIES_DIR}/apache-maven-3.2.5/bin/mvn -PcustomBuild -Dcustom.build.directory=${CMAKE_CURRENT_BINARY_DIR}/java clean compile assembly:single WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
    install(FILES ${CMAKE_CURRENT_BINARY_DIR}/java/sdjagent-1.0-jar-with-dependencies.jar
            DESTINATION ${DRAIOS_BIN_PREFIX}/share RENAME sdjagent.jar
            COMPONENT agent)
endif()
if(JNI_FOUND)
    include(UseJava)
    include_directories(${JAVA_INCLUDE_PATH} ${JAVA_INCLUDE_PATH2})
    add_library(sdjagentjni SHARED native/com_sysdigcloud_sdjagent_CLibrary.h
                                native/com_sysdigcloud_sdjagent_CLibrary.cpp)
    target_link_libraries(sdjagentjni ${JAVA_JVM_LIBRARY})
    install (TARGETS sdjagentjni
             DESTINATION ${DRAIOS_BIN_PREFIX}/lib
             COMPONENT agent)
endif()