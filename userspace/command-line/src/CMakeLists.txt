include_directories(${PROJECT_SOURCE_DIR}/userspace/userspace-shared/src)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/boost_${DRAIOS_BOOST_VERSION})
include_directories(${DRAIOS_DEPENDENCIES_DIR}/poco-${DRAIOS_POCO_VERSION}/target/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/yaml-${DRAIOS_YAML_VERSION}/target/include)

set(COMMAND_LINE_SOURCES command_line_manager.cpp command_line_permission.cpp
                         command_line_permissions.cpp command_line_runnable.cpp
)

list(APPEND command_line_libraries pthread)

list(APPEND command_line_link_libraries userspace-shared)

# Production library
add_library(command-line STATIC ${COMMAND_LINE_SOURCES})
target_link_libraries(command-line userspace-shared)
