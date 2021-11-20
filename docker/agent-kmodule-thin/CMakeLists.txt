foreach(repo dev stable rc)

    file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/${repo})

    add_custom_target(
        agent-kmodule-thin-dockerfile-${repo} ALL
        DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/${repo}/Dockerfile
    )

    if(${CMAKE_SYSTEM_PROCESSOR} STREQUAL "aarch64")
        set(TEMPLATE_FILE "Dockerfile-ubi8-aarch64.jinja2")
    elseif(${CMAKE_SYSTEM_PROCESSOR} STREQUAL "s390x")
        set(TEMPLATE_FILE "Dockerfile-ubi8-s390x.jinja2")
    else()
        set(TEMPLATE_FILE "Dockerfile.jinja2")
    endif()

    add_custom_command(
        OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/${repo}/Dockerfile
        COMMAND
            ${DRAIOS_DEPENDENCIES_DIR}/Python-2.7.16/target/bin/python
            ${CMAKE_CURRENT_SOURCE_DIR}/../generate_agent_docker.py --image agent-kmodule-thin
	    --template ${TEMPLATE_FILE}
            --repo ${repo} > ${CMAKE_CURRENT_BINARY_DIR}/${repo}/Dockerfile
        DEPENDS jinja
        DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/../generate_agent_docker.py
        DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/../${TEMPLATE_FILE}
    )

    add_custom_target(
        agent-kmodule-thin-entrypoint-${repo} ALL
        DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/${repo}/docker-entrypoint.sh
    )

    add_custom_command(
        OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/${repo}/docker-entrypoint.sh
        COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/../docker-entrypoint.sh
                ${CMAKE_CURRENT_BINARY_DIR}/${repo}
        DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/../docker-entrypoint.sh
    )

    add_custom_target(
        agent-kmodule-thin-getrpmurl-${repo} ALL
        DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/${repo}/get-rpm-url.py
    )

    add_custom_command(
        OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/${repo}/get-rpm-url.py
        COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/../get-rpm-url.py
                ${CMAKE_CURRENT_BINARY_DIR}/${repo}
        DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/../get-rpm-url.py
    )

    install(
        FILES ${CMAKE_CURRENT_BINARY_DIR}/${repo}/Dockerfile
        DESTINATION ${CMAKE_INSTALL_PREFIX}/docker/agent-kmodule-thin/${repo}
        COMPONENT dockerfiles
    )

    install(
        PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/${repo}/docker-entrypoint.sh
        DESTINATION ${CMAKE_INSTALL_PREFIX}/docker/agent-kmodule-thin/${repo}
        COMPONENT dockerfiles
    )

    install(
        PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/${repo}/get-rpm-url.py
        DESTINATION ${CMAKE_INSTALL_PREFIX}/docker/agent-kmodule-thin/${repo}
        COMPONENT dockerfiles
    )

endforeach(repo)
