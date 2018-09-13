include_directories(${CMAKE_CURRENT_BINARY_DIR})
include_directories(${DRAIOS_DEPENDENCIES_DIR}/protobuf-${DRAIOS_PROTOBUF_VERSION}/target/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/zlib-${DRAIOS_ZLIB_VERSION})
include_directories(${PROJECT_SOURCE_DIR}/../sysdig/userspace/libscap)
include_directories(${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp)
include_directories(${PROJECT_SOURCE_DIR}/../sysdig/userspace/libsinsp/third-party/jsoncpp)
include_directories(${PROJECT_SOURCE_DIR}/userspace/libsanalyzer)
include_directories(${CMAKE_CURRENT_BINARY_DIR}/../draiosproto)
include_directories(${PROJECT_SOURCE_DIR}/../falco/userspace/engine)
include_directories(${PROJECT_BINARY_DIR}/userspace/engine)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/openssl-${DRAIOS_OPENSSL_VERSION}/target/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/poco-${DRAIOS_POCO_VERSION}/target/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/yaml-${DRAIOS_YAML_VERSION}/target/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/boost_${DRAIOS_BOOST_VERSION})
include_directories(${DRAIOS_DEPENDENCIES_DIR}/curl-${DRAIOS_CURL_VERSION}/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/gperftools-${DRAIOS_GPERFTOOLS_VERSION}/target/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/libb64-${DRAIOS_B64_VERSION}/include)
include_directories(${DRAIOS_DEPENDENCIES_DIR}/jq-${DRAIOS_JQ_VERSION})
include_directories(${DRAIOS_DEPENDENCIES_DIR}/grpc-${DRAIOS_GRPC_VERSION}/include)

add_definitions( -DHAS_ANALYZER )

list(APPEND targetfiles
	baseline_mgr.cpp
	capture_job_handler.cpp
	configuration.cpp
	connection_manager.cpp
	crash_handler.cpp
	dragent.cpp
	error_handler.cpp
	logger.cpp
	monitor.cpp
	protocol.cpp
	security_action.cpp
	security_mgr.cpp
	security_policy.cpp
	sinsp_data_handler.cpp
	sinsp_worker.cpp
	subprocesses_logger.cpp
	user_event_channel.cpp)

if(CYGWIN)
	list(APPEND targetfiles
		windows_helpers.cpp)
endif()

add_library(dragentl STATIC
	${targetfiles})

if(CYGWIN)
	set(POCO_LIB_DIR "bin")
	set(POCO_LIB_PREFIX "cyg")
else()
	set(POCO_LIB_DIR "lib")
	set(POCO_LIB_PREFIX "lib")
endif()

target_link_libraries(dragentl
	falco_engine
        ${DRAIOS_DEPENDENCIES_DIR}/libb64-${DRAIOS_B64_VERSION}/src/libb64.a
	${DRAIOS_DEPENDENCIES_DIR}/poco-${DRAIOS_POCO_VERSION}/target/${POCO_LIB_DIR}/${POCO_LIB_PREFIX}PocoNetSSL.a
	${DRAIOS_DEPENDENCIES_DIR}/poco-${DRAIOS_POCO_VERSION}/target/${POCO_LIB_DIR}/${POCO_LIB_PREFIX}PocoCrypto.a
	${DRAIOS_DEPENDENCIES_DIR}/poco-${DRAIOS_POCO_VERSION}/target/${POCO_LIB_DIR}/${POCO_LIB_PREFIX}PocoUtil.a
	${DRAIOS_DEPENDENCIES_DIR}/poco-${DRAIOS_POCO_VERSION}/target/${POCO_LIB_DIR}/${POCO_LIB_PREFIX}PocoNet.a
	${DRAIOS_DEPENDENCIES_DIR}/poco-${DRAIOS_POCO_VERSION}/target/${POCO_LIB_DIR}/${POCO_LIB_PREFIX}PocoFoundation.a
	${DRAIOS_DEPENDENCIES_DIR}/poco-${DRAIOS_POCO_VERSION}/target/${POCO_LIB_DIR}/${POCO_LIB_PREFIX}PocoCrypto.a
	rt
	${DRAIOS_DEPENDENCIES_DIR}/yaml-${DRAIOS_YAML_VERSION}/target/lib/libyaml-cpp.a)

add_executable(dragent
	main.cpp)

target_link_libraries(dragent
	pthread
	sanalyzer
	dragentl
	draiosproto)

if(NOT CYGWIN)
	target_link_libraries(dragent
		${DRAIOS_DEPENDENCIES_DIR}/openssl-${DRAIOS_OPENSSL_VERSION}/target/lib/libssl.a
		${DRAIOS_DEPENDENCIES_DIR}/openssl-${DRAIOS_OPENSSL_VERSION}/target/lib/libcrypto.a
		${DRAIOS_DEPENDENCIES_DIR}/gperftools-${DRAIOS_GPERFTOOLS_VERSION}/target/lib/libtcmalloc.a)
else()
	target_link_libraries(dragent
		${DRAIOS_DEPENDENCIES_DIR}/openssl-${DRAIOS_OPENSSL_VERSION}/target/lib/libcrypto.a
		/lib/w32api/libiphlpapi.a
	)
endif()

file(COPY ${PROJECT_SOURCE_DIR}/scripts/rpm/dragent.in
	DESTINATION ${PROJECT_BINARY_DIR}/scripts/rpm)

file(COPY root.cert
	DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

file(COPY chisels
	DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

file(COPY ${PROJECT_SOURCE_DIR}/../sysdig/userspace/sysdig/chisels/common.lua
		${PROJECT_SOURCE_DIR}/../sysdig/userspace/sysdig/chisels/dkjson.lua
		DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/chisels)

if (DEFINED AGENT_BUILD_COMMIT OR DEFINED AGENT_BUILD_DATE)
	if (DEFINED AGENT_BUILD_COMMIT)
		file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/.agent_build "commit: ${AGENT_BUILD_COMMIT}\n")
	endif()
	if (DEFINED AGENT_BUILD_DATE)
		file(APPEND ${CMAKE_CURRENT_BINARY_DIR}/.agent_build "build date: ${AGENT_BUILD_DATE}\n")
	endif()
	install(FILES ${CMAKE_CURRENT_BINARY_DIR}/.agent_build
		DESTINATION ${CMAKE_INSTALL_PREFIX}/etc
		COMPONENT agent-slim)
endif()

install(TARGETS dragent
	DESTINATION ${CMAKE_INSTALL_PREFIX}/bin
	COMPONENT agent-slim)

install(FILES root.cert
	DESTINATION ${CMAKE_INSTALL_PREFIX}
	COMPONENT agent-slim)

install(FILES dragent.default.yaml
	DESTINATION ${CMAKE_INSTALL_PREFIX}/etc
	COMPONENT agent-slim)

install(DIRECTORY chisels
	DESTINATION ${CMAKE_INSTALL_PREFIX}/share
	COMPONENT agent-slim)

install(FILES ${PROJECT_SOURCE_DIR}/../sysdig/userspace/sysdig/chisels/common.lua
		${PROJECT_SOURCE_DIR}/../sysdig/userspace/sysdig/chisels/dkjson.lua
		DESTINATION ${CMAKE_INSTALL_PREFIX}/share/chisels
		COMPONENT agent-slim)

if(CYGWIN)
install(FILES ${DRAGENT_WINHAL_DIR}/target/bin/dragent_win_hal.dll
	PERMISSIONS OWNER_EXECUTE OWNER_READ
	DESTINATION ${CMAKE_INSTALL_PREFIX}/bin
	COMPONENT agent-slim)

install(FILES /bin/cygstdc++-6.dll
	PERMISSIONS OWNER_EXECUTE OWNER_READ
	DESTINATION ${CMAKE_INSTALL_PREFIX}/bin
	COMPONENT agent-slim)

install(FILES /bin/cyggcc_s-seh-1.dll
	PERMISSIONS OWNER_EXECUTE OWNER_READ
	DESTINATION ${CMAKE_INSTALL_PREFIX}/bin
	COMPONENT agent-slim)

install(FILES /bin/cygwin1.dll
	PERMISSIONS OWNER_EXECUTE OWNER_READ
	DESTINATION ${CMAKE_INSTALL_PREFIX}/bin
	COMPONENT agent-slim)

install(FILES ${DRAGENT_WINHAL_DIR}/target/bin/DragentService.exe
	PERMISSIONS OWNER_EXECUTE OWNER_READ
	DESTINATION ${CMAKE_INSTALL_PREFIX}
	COMPONENT agent-slim)

install(FILES ${PROJECT_SOURCE_DIR}/windows/wix_installer/dragent.wxs
	DESTINATION ${CMAKE_INSTALL_PREFIX}
	COMPONENT agent-slim)

install(FILES ${PROJECT_SOURCE_DIR}/windows/wix_installer/make_msi.sh
	PERMISSIONS OWNER_EXECUTE OWNER_READ
	DESTINATION ${CMAKE_INSTALL_PREFIX}
	COMPONENT agent-slim)
endif()

configure_file(agent-config.h.in agent-config.h)
