install(FILES run.sh
	DESTINATION ${CMAKE_INSTALL_PREFIX}/test/resources/modules_dir/test-module
	PERMISSIONS OWNER_EXECUTE OWNER_READ
	COMPONENT tests)
