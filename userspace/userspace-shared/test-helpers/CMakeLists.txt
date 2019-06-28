include_directories(${DRAIOS_DEPENDENCIES_DIR}/poco-${DRAIOS_POCO_VERSION}/target/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/yaml-${DRAIOS_YAML_VERSION}/target/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/boost_${DRAIOS_BOOST_VERSION})
include_directories(${PROJECT_SOURCE_DIR}/userspace/userspace-shared/src)

add_library(test-helpers-userspace-shared STATIC
	scoped_configuration.cpp
	scoped_fault.cpp
)

target_compile_definitions(test-helpers-userspace-shared PUBLIC SYSDIG_TEST)
