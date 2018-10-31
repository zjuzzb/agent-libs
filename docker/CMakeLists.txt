add_custom_target(jinja ALL
	DEPENDS ${DRAIOS_DEPENDENCIES_DIR}/Python-2.7.14/target/lib/python2.7/site-packages/jinja2/__init__.py)

add_custom_command(OUTPUT ${DRAIOS_DEPENDENCIES_DIR}/Python-2.7.14/target/lib/python2.7/site-packages/jinja2/__init__.py
	COMMAND ${DRAIOS_DEPENDENCIES_DIR}/Python-2.7.14/target/bin/pip install jinja2)

add_subdirectory(agent-kmodule)
add_subdirectory(agent-slim)
add_subdirectory(agent)
add_subdirectory(local)
