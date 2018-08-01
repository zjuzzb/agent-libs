add_custom_target(jinja_venv ALL
	DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/venvs/jinja2)

add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/venvs/jinja2
	COMMAND ${DRAIOS_DEPENDENCIES_DIR}/Python-2.7.14/target/bin/python -m pip install --user virtualenv &&
         	${DRAIOS_DEPENDENCIES_DIR}/Python-2.7.14/target/bin/python -m virtualenv ${CMAKE_CURRENT_BINARY_DIR}/venvs/jinja2 &&
	        ${CMAKE_CURRENT_BINARY_DIR}/venvs/jinja2/bin/pip install jinja2)

add_subdirectory(agent-kmodule)
add_subdirectory(dev)
add_subdirectory(local)
add_subdirectory(rc)
add_subdirectory(slim)
add_subdirectory(stable)
