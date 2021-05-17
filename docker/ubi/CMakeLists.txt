function(generate_dockerfile image repo)
	add_custom_target(
		dockerfile-${image}-${repo} ALL
		DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/Dockerfile.${image}-${repo}
	)

	add_custom_command(
		OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/Dockerfile.${image}-${repo}
		COMMAND
			${DRAIOS_DEPENDENCIES_DIR}/Python-2.7.16/target/bin/python
			${CMAKE_CURRENT_SOURCE_DIR}/../generate_agent_docker.py --image ${image} --template
			Dockerfile-ubi.jinja2 --repo ${repo} > ${CMAKE_CURRENT_BINARY_DIR}/Dockerfile.${image}-${repo}
		DEPENDS jinja
		DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/../generate_agent_docker.py
		DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/../Dockerfile-ubi.jinja2
	)

    install(
        FILES ${CMAKE_CURRENT_BINARY_DIR}/Dockerfile.${image}-${repo}
        DESTINATION ${CMAKE_INSTALL_PREFIX}/docker/ubi/
        COMPONENT dockerfiles
    )
endfunction()

foreach(image agent agent-kmodule agent-slim)
	foreach(repo dev stable rc)
		generate_dockerfile(${image} ${repo})
	endforeach(repo)
endforeach(image)

generate_dockerfile(local dev)

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

