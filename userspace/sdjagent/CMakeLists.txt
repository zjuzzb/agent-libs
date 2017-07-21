find_package(Java 1.6 COMPONENTS Development)
find_package(JNI)

if(Java_Development_FOUND)
    add_custom_target(sdjagent ALL DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/java/sdjagent-1.0-jar-with-dependencies.jar)
    add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/java/sdjagent-1.0-jar-with-dependencies.jar
            COMMAND JAVA_HOME=${JAVA_HOME}
            ${DRAIOS_DEPENDENCIES_DIR}/apache-maven-3.2.5/bin/mvn -q -PcustomBuild
            -Dcustom.build.directory=${CMAKE_CURRENT_BINARY_DIR}/java compile assembly:single
            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
            DEPENDS src/main/java/com/sysdigcloud/sdjagent/ApplicationLoader.java
                    src/main/java/com/sysdigcloud/sdjagent/Application.java
                    src/main/java/com/sysdigcloud/sdjagent/AttachAPI.java
                    src/main/java/com/sysdigcloud/sdjagent/BeanData.java
                    src/main/java/com/sysdigcloud/sdjagent/CLibrary.java
                    src/main/java/com/sysdigcloud/sdjagent/Config.java
                    src/main/java/com/sysdigcloud/sdjagent/Connection.java
                    src/main/java/com/sysdigcloud/sdjagent/JvmstatVM.java
                    src/main/java/com/sysdigcloud/sdjagent/LogJsonFormatter.java
                    src/main/java/com/sysdigcloud/sdjagent/MonitoredVM.java
                    src/main/java/com/sysdigcloud/sdjagent/PosixQueue.java
                    src/main/java/com/sysdigcloud/sdjagent/VMRequest.java
                    src/main/java/com/sysdigcloud/sdjagent/YamlConfig.java
                    pom.xml)
    install(FILES ${CMAKE_CURRENT_BINARY_DIR}/java/sdjagent-1.0-jar-with-dependencies.jar
            DESTINATION ${DRAIOS_BIN_PREFIX}/share RENAME sdjagent.jar
            COMPONENT agent)
endif()
if(JNI_FOUND)
    include(UseJava)
    include_directories(${JAVA_INCLUDE_PATH} ${JAVA_INCLUDE_PATH2})
    add_library(sdjagentjni SHARED
            native/com_sysdigcloud_sdjagent_CLibrary.h
            native/com_sysdigcloud_sdjagent_CLibrary.cpp
            native/com_sysdigcloud_sdjagent_PosixQueue.h
            native/com_sysdigcloud_sdjagent_PosixQueue.cpp
            native/jni_utils.h)
    target_link_libraries(sdjagentjni ${JAVA_JVM_LIBRARY} rt)
    install (TARGETS sdjagentjni
             DESTINATION ${DRAIOS_BIN_PREFIX}/lib
             COMPONENT agent)
endif()
