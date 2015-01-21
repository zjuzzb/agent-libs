find_package(Java REQUIRED)
find_package(JNI REQUIRED)
include(UseJava)

include_directories(${JAVA_INCLUDE_PATH} ${JAVA_INCLUDE_PATH2})
add_library(sdjagentjni SHARED native/com_sysdigcloud_sdjagent_CLibrary.h
                            native/com_sysdigcloud_sdjagent_CLibrary.cpp)
target_link_libraries(sdjagentjni ${JNI_LIBRARIES})

add_custom_target(sdjagent ALL COMMAND mvn -PcustomBuild -Dcustom.build.directory=${CMAKE_CURRENT_BINARY_DIR}/java clean compile assembly:single WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/java/sdjagent-1.0-jar-with-dependencies.jar
	    DESTINATION ${DRAIOS_BIN_PREFIX}/share RENAME sdjagent.jar
	    COMPONENT agent)
install (TARGETS sdjagentjni 
	     DESTINATION ${DRAIOS_BIN_PREFIX}/lib
	     COMPONENT agent)