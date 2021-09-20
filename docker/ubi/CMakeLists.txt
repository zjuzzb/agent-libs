function(generate_dockerfile image repo template)
	add_custom_target(
		dockerfile-${image}-${repo} ALL
		DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/Dockerfile.${image}-${repo}
	)

	add_custom_command(
		OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/Dockerfile.${image}-${repo}
		COMMAND
			${DRAIOS_DEPENDENCIES_DIR}/Python-2.7.16/target/bin/python
			${CMAKE_CURRENT_SOURCE_DIR}/../generate_agent_docker.py --image ${image} --template
			${template} --repo ${repo} > ${CMAKE_CURRENT_BINARY_DIR}/Dockerfile.${image}-${repo}
		DEPENDS jinja
		DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/../generate_agent_docker.py
		DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/../${template}
	)

    install(
        FILES ${CMAKE_CURRENT_BINARY_DIR}/Dockerfile.${image}-${repo}
        DESTINATION ${CMAKE_INSTALL_PREFIX}/docker/ubi/
        COMPONENT dockerfiles
    )
endfunction()

foreach(image agent agent-kmodule)
	foreach(repo dev stable rc)
		generate_dockerfile(${image} ${repo} Dockerfile-ubi.jinja2)
	endforeach(repo)
endforeach(image)

foreach(repo dev stable rc)
	generate_dockerfile(agent-slim ${repo} Dockerfile-ubi8.jinja2)
endforeach(repo)

generate_dockerfile(local dev Dockerfile-ubi.jinja2)

install(
	PROGRAMS ${CMAKE_CURRENT_SOURCE_DIR}/../docker-entrypoint.sh
	DESTINATION ${CMAKE_INSTALL_PREFIX}/docker/ubi/
	COMPONENT dockerfiles
)

install(
	PROGRAMS ${CMAKE_CURRENT_SOURCE_DIR}/../get-rpm-url.py
	DESTINATION ${CMAKE_INSTALL_PREFIX}/docker/ubi/
	COMPONENT dockerfiles
)

