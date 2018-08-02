foreach(repo dev stable rc)

file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/${repo})

add_custom_target(agent-kmodule-dockerfile-${repo} ALL
	DEPENDS jinja_venv
	DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/${repo}/Dockerfile)

add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/${repo}/Dockerfile
	COMMAND ${CMAKE_CURRENT_BINARY_DIR}/../venvs/jinja2/bin/python ${CMAKE_CURRENT_SOURCE_DIR}/../generate_agent_docker.py --image agent-kmodule --repo ${repo} > ${CMAKE_CURRENT_BINARY_DIR}/${repo}/Dockerfile)

add_custom_target(agent-kmodule-entrypoint-${repo} ALL
	DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/${repo}/docker-entrypoint.sh)

add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/${repo}/docker-entrypoint.sh
	COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/../docker-entrypoint.sh ${CMAKE_CURRENT_BINARY_DIR}/${repo})

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/${repo}/Dockerfile
	DESTINATION ${CMAKE_INSTALL_PREFIX}/docker/agent-kmodule/${repo}
	COMPONENT dockerfiles)

install(PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/${repo}/docker-entrypoint.sh
	DESTINATION ${CMAKE_INSTALL_PREFIX}/docker/agent-kmodule/${repo}
	COMPONENT dockerfiles)

endforeach(repo)
