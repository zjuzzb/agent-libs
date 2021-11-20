add_custom_target(local-ubi-dockerfile ALL DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/Dockerfile)

# UBI-8 only for aarch64 and s390x
if(${CMAKE_SYSTEM_PROCESSOR} STREQUAL "aarch64")
    set(TEMPLATE_FILE "Dockerfile-ubi8-aarch64.jinja2")
elseif(${CMAKE_SYSTEM_PROCESSOR} STREQUAL "s390x")
    set(TEMPLATE_FILE "Dockerfile-ubi8-s390x.jinja2")
else()
    set(TEMPLATE_FILE "Dockerfile-ubi.jinja2")
endif()

add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/Dockerfile
    COMMAND
        ${DRAIOS_DEPENDENCIES_DIR}/Python-2.7.16/target/bin/python
        ${CMAKE_CURRENT_SOURCE_DIR}/../generate_agent_docker.py --image local --template
        ${TEMPLATE_FILE} --repo dev > ${CMAKE_CURRENT_BINARY_DIR}/Dockerfile
    DEPENDS jinja
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/../generate_agent_docker.py
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/../${TEMPLATE_FILE}
)

add_custom_target(local-ubi-entrypoint ALL DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/docker-entrypoint.sh)

add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/docker-entrypoint.sh
    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/../docker-entrypoint.sh
            ${CMAKE_CURRENT_BINARY_DIR}
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/../docker-entrypoint.sh
)

add_custom_target(local-ubi-getrpmurl ALL DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/get-rpm-url.py)

add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/get-rpm-url.py
    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/../get-rpm-url.py
            ${CMAKE_CURRENT_BINARY_DIR}
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/../get-rpm-url.py
)

install(
    FILES ${CMAKE_CURRENT_BINARY_DIR}/Dockerfile
    DESTINATION ${CMAKE_INSTALL_PREFIX}/docker/local-ubi
    COMPONENT dockerfiles
)

install(
    PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/docker-entrypoint.sh
    DESTINATION ${CMAKE_INSTALL_PREFIX}/docker/local-ubi
    COMPONENT dockerfiles
)

install(
    PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/get-rpm-url.py
    DESTINATION ${CMAKE_INSTALL_PREFIX}/docker/local-ubi
    COMPONENT dockerfiles
)
