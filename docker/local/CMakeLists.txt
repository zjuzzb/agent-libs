add_custom_target(local-dockerfile ALL
	DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/Dockerfile)

add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/Dockerfile
	COMMAND ${DRAIOS_DEPENDENCIES_DIR}/Python-2.7.14/target/bin/python ${CMAKE_CURRENT_SOURCE_DIR}/../generate_agent_docker.py --image local --repo dev > ${CMAKE_CURRENT_BINARY_DIR}/Dockerfile
	DEPENDS jinja
	DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/../generate_agent_docker.py
	DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/../Dockerfile.jinja2
	)

add_custom_target(local-entrypoint ALL
	DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/docker-entrypoint.sh)

add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/docker-entrypoint.sh
	COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/../docker-entrypoint.sh ${CMAKE_CURRENT_BINARY_DIR}
	DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/../docker-entrypoint.sh
	)

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/Dockerfile
	DESTINATION ${CMAKE_INSTALL_PREFIX}/docker/local
	COMPONENT dockerfiles)

install(PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/docker-entrypoint.sh
	DESTINATION ${CMAKE_INSTALL_PREFIX}/docker/local
	COMPONENT dockerfiles)
