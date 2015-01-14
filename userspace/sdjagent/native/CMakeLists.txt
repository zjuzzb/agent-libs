find_package(Java REQUIRED)
find_package(JNI REQUIRED)
include(UseJava)

include_directories(${JAVA_INCLUDE_PATH} ${JAVA_INCLUDE_PATH2})
add_library(sdjagent SHARED com_sysdigcloud_sdjagent_CLibrary.h
                            com_sysdigcloud_sdjagent_CLibrary.cpp)
target_link_libraries(sdjagent ${JNI_LIBRARIES})