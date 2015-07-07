find_package(PythonInterp)
add_custom_target(sdchecks ALL COMMAND python -m compileall ${CMAKE_CURRENT_SOURCE_DIR})
add_custom_target(sdchecks_deps ALL COMMAND pip install --ignore-installed --install-option="--prefix=${CMAKE_CURRENT_BINARY_DIR}/deps" -r ${CMAKE_CURRENT_SOURCE_DIR}/requirements.txt)
add_dependencies(sdchecks sdchecks_deps)
install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/ DESTINATION ${DRAIOS_BIN_PREFIX}/lib/python COMPONENT agent FILES_MATCHING PATTERN *.py*)
install(DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/deps/lib/python${PYTHON_VERSION_MAJOR}.${PYTHON_VERSION_MINOR}/site-packages DESTINATION ${DRAIOS_BIN_PREFIX}/lib/python COMPONENT agent)
install(PROGRAMS sdchecks
	DESTINATION ${DRAIOS_BIN_PREFIX}/bin
	COMPONENT agent)