foreach(repo dev stable rc)

file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/${repo})

add_custom_target(agent-slim-dockerfile-${repo} ALL
	DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/${repo}/Dockerfile)

add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/${repo}/Dockerfile
	COMMAND ${DRAIOS_DEPENDENCIES_DIR}/Python-2.7.14/target/bin/python ${CMAKE_CURRENT_SOURCE_DIR}/../generate_agent_docker.py --image agent-slim --repo ${repo} > ${CMAKE_CURRENT_BINARY_DIR}/${repo}/Dockerfile
	DEPENDS jinja
	DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/../generate_agent_docker.py
	DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/../Dockerfile.jinja2
	)

add_custom_target(agent-slim-entrypoint-${repo} ALL
	DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/${repo}/docker-entrypoint.sh)

add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/${repo}/docker-entrypoint.sh
	COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/../docker-entrypoint.sh ${CMAKE_CURRENT_BINARY_DIR}/${repo}
	DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/../docker-entrypoint.sh
	)

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/${repo}/Dockerfile
	DESTINATION ${CMAKE_INSTALL_PREFIX}/docker/agent-slim/${repo}
	COMPONENT dockerfiles)

install(PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/${repo}/docker-entrypoint.sh
	DESTINATION ${CMAKE_INSTALL_PREFIX}/docker/agent-slim/${repo}
	COMPONENT dockerfiles)

endforeach(repo)
