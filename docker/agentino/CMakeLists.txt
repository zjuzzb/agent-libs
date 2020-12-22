foreach(repo dev stable rc)
    file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/${repo})

    add_custom_command(
        OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/${repo}/Dockerfile
        COMMAND
            sed 's/SYSDIG_REPOSITORY PLACEHOLDER_SEE_CMAKE_FILE/SYSDIG_REPOSITORY ${repo}/g'
            ${CMAKE_CURRENT_SOURCE_DIR}/Dockerfile > ${CMAKE_CURRENT_BINARY_DIR}/${repo}/Dockerfile
        DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/Dockerfile
    )

    add_custom_command(
        OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/${repo}/agentino-entrypoint.sh
        COMMAND cp ${CMAKE_CURRENT_SOURCE_DIR}/agentino-entrypoint.sh
                ${CMAKE_CURRENT_BINARY_DIR}/${repo}
        DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/agentino-entrypoint.sh
    )

    install(
        FILES ${CMAKE_CURRENT_BINARY_DIR}/${repo}/Dockerfile
        DESTINATION ${CMAKE_INSTALL_PREFIX}/docker/agentino/${repo}
        COMPONENT dockerfiles
    )

    install(
        PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/${repo}/agentino-entrypoint.sh
        DESTINATION ${CMAKE_INSTALL_PREFIX}/docker/agentino/${repo}
        COMPONENT dockerfiles
    )

    list(APPEND targetfiles ${CMAKE_CURRENT_BINARY_DIR}/${repo}/Dockerfile
         ${CMAKE_CURRENT_BINARY_DIR}/${repo}/agentino-entrypoint.sh
    )

endforeach(repo)

file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/local)

add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/local/Dockerfile
    COMMAND cp ${CMAKE_CURRENT_SOURCE_DIR}/Dockerfile.local
            ${CMAKE_CURRENT_BINARY_DIR}/local/Dockerfile
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/Dockerfile.local
)

add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/local/agentino-entrypoint.sh
    COMMAND cp ${CMAKE_CURRENT_SOURCE_DIR}/agentino-entrypoint.sh ${CMAKE_CURRENT_BINARY_DIR}/local
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/agentino-entrypoint.sh
)

install(
    FILES ${CMAKE_CURRENT_BINARY_DIR}/local/Dockerfile
    DESTINATION ${CMAKE_INSTALL_PREFIX}/docker/agentino/local
    COMPONENT dockerfiles
)

install(
    PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/local/agentino-entrypoint.sh
    DESTINATION ${CMAKE_INSTALL_PREFIX}/docker/agentino/local
    COMPONENT dockerfiles
)

list(APPEND targetfiles ${CMAKE_CURRENT_BINARY_DIR}/local/Dockerfile
     ${CMAKE_CURRENT_BINARY_DIR}/local/agentino-entrypoint.sh
)

file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/static)

add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/static/Dockerfile
    COMMAND cp ${CMAKE_CURRENT_SOURCE_DIR}/Dockerfile.static
            ${CMAKE_CURRENT_BINARY_DIR}/static/Dockerfile
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/Dockerfile.static
)

add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/static/agentino-entrypoint.sh
    COMMAND cp ${CMAKE_CURRENT_SOURCE_DIR}/agentino-entrypoint.sh ${CMAKE_CURRENT_BINARY_DIR}/static
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/agentino-entrypoint.sh
)

install(
    FILES ${CMAKE_CURRENT_BINARY_DIR}/static/Dockerfile
    DESTINATION ${CMAKE_INSTALL_PREFIX}/docker/agentino/static
    COMPONENT dockerfiles
)

install(
    PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/static/agentino-entrypoint.sh
    DESTINATION ${CMAKE_INSTALL_PREFIX}/docker/agentino/static
    COMPONENT dockerfiles
)

list(APPEND targetfiles ${CMAKE_CURRENT_BINARY_DIR}/static/Dockerfile
     ${CMAKE_CURRENT_BINARY_DIR}/static/agentino-entrypoint.sh
)

add_custom_target(agentino-dockerfiles ALL DEPENDS ${targetfiles})
