include_directories(${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/third-party/jsoncpp)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/poco-${DRAIOS_POCO_VERSION}/target/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/yaml-${DRAIOS_YAML_VERSION}/target/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/boost_${DRAIOS_BOOST_VERSION})

add_library(userspace-shared STATIC
	configuration_manager.cpp
	configuration_unit.cpp
	${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/third-party/jsoncpp/jsoncpp.cpp
)
