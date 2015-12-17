add_custom_target(sdchecks ALL
	COMMAND ${CMAKE_COMMAND} -E env PATH="${DRAIOS_DEPENDENCIES_DIR}/postgresql-9.4.5/target/bin:$ENV{PATH}" ${DRAIOS_DEPENDENCIES_DIR}/Python-2.7.10/target/bin/python ${DRAIOS_DEPENDENCIES_DIR}/Python-2.7.10/target/bin/pip install -I --target=${CMAKE_CURRENT_BINARY_DIR}/deps --upgrade -r ${CMAKE_CURRENT_SOURCE_DIR}/requirements.txt)
#add_custom_command(TARGET sdchecks POST_BUILD COMMAND find ${CMAKE_CURRENT_BINARY_DIR}/deps -iname "*.egg-info" -exec rm -rf "{}" \; )
install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/ DESTINATION ${DRAIOS_BIN_PREFIX}/lib/python COMPONENT agent FILES_MATCHING PATTERN *.py)
install(DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/deps/ DESTINATION ${DRAIOS_BIN_PREFIX}/lib/python-deps COMPONENT agent FILES_MATCHING PATTERN *.py)
install(DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/deps/ DESTINATION ${DRAIOS_BIN_PREFIX}/lib/python-deps COMPONENT agent FILES_MATCHING PATTERN *.so)
install(DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/deps/ DESTINATION ${DRAIOS_BIN_PREFIX}/lib/python-deps COMPONENT agent FILES_MATCHING PATTERN *.pth)
install(FILES
		${DRAIOS_DEPENDENCIES_DIR}/postgresql-9.4.5/target/lib/libpq.so.5.7
		DESTINATION ${DRAIOS_BIN_PREFIX}/lib/ COMPONENT agent RENAME libpq.so.5)
install(PROGRAMS sdchecks
	DESTINATION ${DRAIOS_BIN_PREFIX}/bin
	COMPONENT agent)