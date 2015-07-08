#find_package(PythonInterp)
add_custom_target(sdchecks ALL COMMAND ${DRAIOS_DEPENDENCIES_DIR}/Python-2.7.10/target/bin/python -m compileall ${CMAKE_CURRENT_SOURCE_DIR})
add_custom_command(TARGET sdchecks PRE_BUILD COMMAND ${DRAIOS_DEPENDENCIES_DIR}/Python-2.7.10/target/bin/pip install -I --target=${CMAKE_CURRENT_BINARY_DIR}/deps --upgrade -r ${CMAKE_CURRENT_SOURCE_DIR}/requirements.txt)
#add_custom_command(TARGET sdchecks POST_BUILD COMMAND find ${CMAKE_CURRENT_BINARY_DIR}/deps -iname "*.egg-info" -exec rm -rf "{}" \; )
install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/ DESTINATION ${DRAIOS_BIN_PREFIX}/lib/python COMPONENT agent FILES_MATCHING PATTERN *.py*)
install(DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/deps/ DESTINATION ${DRAIOS_BIN_PREFIX}/lib/python-deps COMPONENT agent)
install(PROGRAMS sdchecks
	DESTINATION ${DRAIOS_BIN_PREFIX}/bin
	COMPONENT agent)