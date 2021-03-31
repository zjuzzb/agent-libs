foreach(repo dev fargate-rc)
    file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/${repo})

    add_custom_command(
        OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/${repo}/Dockerfile
        COMMAND
            sed 's/SYSDIG_REPOSITORY PLACEHOLDER_SEE_CMAKE_FILE/SYSDIG_REPOSITORY ${repo}/g'
            ${CMAKE_CURRENT_SOURCE_DIR}/Dockerfile > ${CMAKE_CURRENT_BINARY_DIR}/${repo}/Dockerfile
        DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/Dockerfile
    )

    add_custom_command(
        OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/${repo}/agentone-entrypoint.sh
        COMMAND cp ${CMAKE_CURRENT_SOURCE_DIR}/agentone-entrypoint.sh
                ${CMAKE_CURRENT_BINARY_DIR}/${repo}
        DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/agentone-entrypoint.sh
    )

    install(
        FILES ${CMAKE_CURRENT_BINARY_DIR}/${repo}/Dockerfile
        DESTINATION ${CMAKE_INSTALL_PREFIX}/docker/agentone/${repo}
        COMPONENT dockerfiles
    )

    install(
        PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/${repo}/agentone-entrypoint.sh
        DESTINATION ${CMAKE_INSTALL_PREFIX}/docker/agentone/${repo}
        COMPONENT dockerfiles
    )

    list(APPEND targetfiles ${CMAKE_CURRENT_BINARY_DIR}/${repo}/Dockerfile
         ${CMAKE_CURRENT_BINARY_DIR}/${repo}/agentone-entrypoint.sh
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
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/local/agentone-entrypoint.sh
    COMMAND cp ${CMAKE_CURRENT_SOURCE_DIR}/agentone-entrypoint.sh ${CMAKE_CURRENT_BINARY_DIR}/local
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/agentone-entrypoint.sh
)

install(
    FILES ${CMAKE_CURRENT_BINARY_DIR}/local/Dockerfile
    DESTINATION ${CMAKE_INSTALL_PREFIX}/docker/agentone/local
    COMPONENT dockerfiles
)

install(
    PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/local/agentone-entrypoint.sh
    DESTINATION ${CMAKE_INSTALL_PREFIX}/docker/agentone/local
    COMPONENT dockerfiles
)

list(APPEND targetfiles ${CMAKE_CURRENT_BINARY_DIR}/local/Dockerfile
     ${CMAKE_CURRENT_BINARY_DIR}/local/agentone-entrypoint.sh
)

add_custom_target(agentone-dockerfiles ALL DEPENDS ${targetfiles})
