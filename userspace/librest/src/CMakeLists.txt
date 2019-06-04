include_directories(${DRAIOS_DEPENDENCIES_DIR}/poco-${DRAIOS_POCO_VERSION}/target/include)

set(LIBREST_SOURCES
	rest_exception.cpp
	rest_request_handler.cpp
	rest_request_handler_factory.cpp
	rest_server.cpp
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
