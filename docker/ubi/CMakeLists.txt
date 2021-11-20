function(generate_dockerfile image repo template_file_base)
	if(${CMAKE_SYSTEM_PROCESSOR} STREQUAL "aarch64")
	    set(TEMPLATE_FILE "${template_file_base}-aarch64.jinja2")
	elseif(${CMAKE_SYSTEM_PROCESSOR} STREQUAL "s390x")
	    set(TEMPLATE_FILE "${template_file_base}-s390x.jinja2")
	else()
	    set(TEMPLATE_FILE "${template_file_base}.jinja2")
	endif()

	add_custom_target(
		dockerfile-${image}-${repo} ALL
		DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/Dockerfile.${image}-${repo}
	)

	add_custom_command(
		OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/Dockerfile.${image}-${repo}
		COMMAND
			${DRAIOS_DEPENDENCIES_DIR}/Python-2.7.16/target/bin/python
			${CMAKE_CURRENT_SOURCE_DIR}/../generate_agent_docker.py
			--image ${image} --template ${TEMPLATE_FILE}
			--repo ${repo} > ${CMAKE_CURRENT_BINARY_DIR}/Dockerfile.${image}-${repo}
		DEPENDS jinja
		DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/../generate_agent_docker.py
		DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/../${TEMPLATE_FILE}
	)

    install(
        FILES ${CMAKE_CURRENT_BINARY_DIR}/Dockerfile.${image}-${repo}
        DESTINATION ${CMAKE_INSTALL_PREFIX}/docker/ubi/
        COMPONENT dockerfiles
    )
endfunction()

foreach(image agent agent-kmodule)
	foreach(repo dev stable rc)
		# UBI-8 only for aarch64 and s390x
		if((${CMAKE_SYSTEM_PROCESSOR} STREQUAL "aarch64") OR (${CMAKE_SYSTEM_PROCESSOR} STREQUAL "s390x"))
			generate_dockerfile(${image} ${repo} Dockerfile-ubi8)
		else()
			generate_dockerfile(${image} ${repo} Dockerfile-ubi)
		endif()
	endforeach(repo)
endforeach(image)

foreach(repo dev stable rc)
	generate_dockerfile(agent-slim ${repo} Dockerfile-ubi8)
endforeach(repo)

# UBI-8 only for aarch64 and s390x
if((${CMAKE_SYSTEM_PROCESSOR} STREQUAL "aarch64") OR (${CMAKE_SYSTEM_PROCESSOR} STREQUAL "s390x"))
	generate_dockerfile(local dev Dockerfile-ubi8)
else()
	generate_dockerfile(local dev Dockerfile-ubi)
endif()

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

install(
    PROGRAMS ${PROBE_LOADER_DIR}/sysdig-probe-loader
    DESTINATION ${CMAKE_INSTALL_PREFIX}/docker/ubi
    RENAME sysdigcloud-probe-loader
    COMPONENT dockerfiles
)

install(
    PROGRAMS get-version-and-exec.sh
    DESTINATION ${CMAKE_INSTALL_PREFIX}/docker/ubi
    COMPONENT dockerfiles
)
