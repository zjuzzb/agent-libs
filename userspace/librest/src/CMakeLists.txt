include_directories(${DRAIOS_DEPENDENCIES_DIR}/poco-${DRAIOS_POCO_VERSION}/target/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/yaml-${DRAIOS_YAML_VERSION}/target/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/boost_${DRAIOS_BOOST_VERSION})
include_directories(${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/third-party/jsoncpp)
include_directories(${PROJECT_SOURCE_DIR}/userspace/userspace-shared/src)

set(LIBREST_SOURCES
	rest_exception.cpp
	rest_request_handler.cpp
	rest_request_handler_factory.cpp
	rest_server.cpp
	rest_util.cpp
)

list(APPEND librest_link_libraries
	${DRAIOS_DEPENDENCIES_DIR}/poco-${DRAIOS_POCO_VERSION}/target/lib/libPocoUtil.a
	${DRAIOS_DEPENDENCIES_DIR}/poco-${DRAIOS_POCO_VERSION}/target/lib/libPocoNet.a
	${DRAIOS_DEPENDENCIES_DIR}/poco-${DRAIOS_POCO_VERSION}/target/lib/libPocoFoundation.a
	pthread
)

# Production library
add_library(librestl STATIC ${LIBREST_SOURCES})
target_link_libraries(librestl ${librest_link_libraries})
