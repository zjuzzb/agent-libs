add_custom_target(dev-dockerfile ALL
	DEPENDS jinja_venv
	DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/Dockerfile)

add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/Dockerfile
	COMMAND ${CMAKE_CURRENT_BINARY_DIR}/../venvs/jinja2/bin/python ${CMAKE_CURRENT_SOURCE_DIR}/../generate_agent_docker.py --variant dev > ${CMAKE_CURRENT_BINARY_DIR}/Dockerfile)

add_custom_target(dev-entrypoint ALL
	DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/docker-entrypoint.sh)

add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/docker-entrypoint.sh
	COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/../docker-entrypoint.sh ${CMAKE_CURRENT_BINARY_DIR})

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/Dockerfile ${CMAKE_CURRENT_BINARY_DIR}/docker-entrypoint.sh
	DESTINATION ${DRAIOS_BIN_PREFIX}/docker/dev
	COMPONENT dockerfiles)
