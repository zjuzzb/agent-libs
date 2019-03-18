cmake_minimum_required(VERSION 2.6)

project(draios)

option(BUILD_WARNINGS_AS_ERRORS "Enable building with -Wextra -Werror flags")

# Versions of all third-party libraries used. These may be referred to
# in lower CMakeLists.txt files.
set(DRAIOS_OPENSSL_VERSION "1.0.2n")
set(DRAIOS_PROTOBUF_VERSION "3.6.1")
if(NOT CYGWIN)
set(DRAIOS_ZLIB_VERSION "1.2.11")
else()
set(DRAIOS_ZLIB_VERSION "1.2.8")
endif()
set(DRAIOS_POCO_VERSION "1.9.0-all")
set(DRAIOS_GTEST_VERSION "1.7.0")
set(DRAIOS_YAML_VERSION "cpp-0.5.1")
set(DRAIOS_BOOST_VERSION "1_57_0")
set(DRAIOS_CURL_VERSION "7.57.0")
set(DRAIOS_JQ_VERSION "1.5")
set(DRAIOS_B64_VERSION "1.2")
set(DRAIOS_GRPC_VERSION "1.8.1")
set(DRAIOS_GPERFTOOLS_VERSION "2.5")
if(CYGWIN)
	set(DRAIOS_LUAJIT_VERSION "2.0.5")
else()
	set(DRAIOS_LUAJIT_VERSION "2.0.3")
endif()
set(DRAIOS_CARES_VERSION "1.13.0")
set(DRAIOS_KUBECTL_VERSION "1.9.6")
set(DRAIOS_KUBE_BENCH_VERSION "0.0.24.1")
if(NOT CYGWIN)
	set(DRAIOS_TBB_VERSION "2018_U5")
endif()
set(DRAIOS_NJSON_VERSION "3.3.0")

set(DRAIOS_DEBUG_FLAGS "-D_DEBUG")
#set(DRAIOS_FEATURE_FLAGS "-DPPM_ENABLE_SENTINEL")

set(CMAKE_COMMON_FLAGS "-Wall -ggdb ${DRAIOS_FEATURE_FLAGS}")
if(BUILD_WARNINGS_AS_ERRORS)
	set(CMAKE_SUPPRESSED_WARNINGS "-Wno-unused-parameter -Wno-missing-field-initializers -Wno-sign-compare -Wno-type-limits")
	set(CMAKE_COMMON_FLAGS "${CMAKE_COMMON_FLAGS} -Wextra -Werror ${CMAKE_SUPPRESSED_WARNINGS}")
endif()
set(CMAKE_C_FLAGS "-std=gnu11 ${CMAKE_COMMON_FLAGS}")
set(CMAKE_CXX_FLAGS "--std=c++0x ${CMAKE_COMMON_FLAGS}")
set(CMAKE_C_FLAGS_DEBUG "${DRAIOS_DEBUG_FLAGS}")
set(CMAKE_CXX_FLAGS_DEBUG "${DRAIOS_DEBUG_FLAGS}")
# Add "-fno-inline -fno-omit-frame-pointer" for perf
set(CMAKE_C_FLAGS_RELEASE "-O3 -fno-strict-aliasing -DNDEBUG")
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -fno-strict-aliasing -DNDEBUG")

add_definitions(-DPLATFORM_NAME="${CMAKE_SYSTEM_NAME}")
add_definitions(-DHAS_CAPTURE)
if(CYGWIN)
	add_definitions(-DCYGWING_AGENT)
endif()

add_definitions(-D_GNU_SOURCE)

if(DEFINED ENV{CMAKE_INSTALL_PREFIX})
	set (CMAKE_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}")
endif()

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
	set(KBUILD_FLAGS "${DRAIOS_DEBUG_FLAGS} ${DRAIOS_FEATURE_FLAGS}")
	set(CPACK_STRIP_FILES "OFF")
else()
	set(KBUILD_FLAGS "${DRAIOS_FEATURE_FLAGS}")
	set(CPACK_STRIP_FILES "ON")
endif()

set(PACKAGE_NAME "draios-agent")
set(PROBE_VERSION "${AGENT_VERSION}")
set(PROBE_NAME "sysdigcloud-probe")
set(PROBE_DEVICE_NAME "sysdigcloud")

if(NOT CYGWIN)
	add_subdirectory(${PROJECT_SOURCE_DIR}/../sysdig/driver ${PROJECT_BINARY_DIR}/driver)
	set(ZLIB_INCLUDE "${DRAIOS_DEPENDENCIES_DIR}/zlib-1.2.11")
	set(ZLIB_LIB "${DRAIOS_DEPENDENCIES_DIR}/zlib-1.2.11/libz.a")
else()
	set(ZLIB_INCLUDE "${DRAIOS_DEPENDENCIES_DIR}/zlib-1.2.8")
	set(ZLIB_LIB "${DRAIOS_DEPENDENCIES_DIR}/zlib-1.2.8/libz.a")
endif()

add_custom_target(zlib)

if(NOT CYGWIN)
	if(EXISTS "${DRAIOS_DEPENDENCIES_DIR}/LuaJIT-2.0.3/src")
		set(LUAJIT_INCLUDE "${DRAIOS_DEPENDENCIES_DIR}/LuaJIT-2.0.3/src")
		set(LUALIB "${LUAJIT_INCLUDE}/libluajit.a")
	else()
		set(LUAJIT_INCLUDE "${DRAIOS_DEPENDENCIES_DIR}/lua-5.1.5/src")
		set(LUALIB "${LUAJIT_INCLUDE}/liblua.a")
	endif()
	set(CURL_INCLUDE_DIR "${DRAIOS_DEPENDENCIES_DIR}/curl-7.57.0/include")
	set(TBB_INCLUDE_DIR "${DRAIOS_DEPENDENCIES_DIR}/tbb-${DRAIOS_TBB_VERSION}/include/")
else()
	set(LUAJIT_INCLUDE "${DRAIOS_DEPENDENCIES_DIR}/LuaJIT-2.0.5/src")
	set(LUALIB "${LUAJIT_INCLUDE}/libluajit.a")
	set(CURL_INCLUDE_DIR "${DRAIOS_DEPENDENCIES_DIR}/curl-7.57.0/include")
	set(WIN_HAL_INCLUDE "${DRAGENT_WINHAL_DIR}/target/include")
	set(WIN_HAL_LIB "${DRAGENT_WINHAL_DIR}/target/lib")
endif()

set(NJSON_INCLUDE "${DRAIOS_DEPENDENCIES_DIR}/json-3.3.0/single_include")
set(LPEG_LIB "${DRAIOS_DEPENDENCIES_DIR}/lpeg-1.0.0/target/lpeg.a")
set(LYAML_LIB "${DRAIOS_DEPENDENCIES_DIR}/lyaml-release-v6.0/target/lib/lua/5.1/yaml.a")
set(LIBYAML_LIB "${DRAIOS_DEPENDENCIES_DIR}/libyaml-0.1.7/target/lib/libyaml.a")
set(FALCO_SINSP_LIBRARY sanalyzer)
set(FALCO_SHARE_DIR "${CMAKE_INSTALL_PREFIX}/share")
set(FALCO_ABSOLUTE_SHARE_DIR "${FALCO_SHARE_DIR}")
set(FALCO_COMPONENT agent-slim)
add_subdirectory(${PROJECT_SOURCE_DIR}/../oss-falco/userspace/engine ${PROJECT_BINARY_DIR}/userspace/engine)

add_subdirectory(${PROJECT_SOURCE_DIR}/../sysdig/userspace/libscap ${PROJECT_BINARY_DIR}/libscap)
if(NOT CYGWIN)
	add_subdirectory(userspace/cointerface)
endif()
add_subdirectory(userspace/comp_modules)
add_subdirectory(userspace/dragent/src)
add_subdirectory(userspace/dragent/test)
add_subdirectory(userspace/draiosproto)
add_subdirectory(userspace/libsanalyzer/src)
add_subdirectory(userspace/libsanalyzer/test)
add_subdirectory(userspace/libsanalyzer/tests)
add_subdirectory(userspace/test_helpers/src)
add_subdirectory(userspace/test_helpers/test)
if(NOT CYGWIN)
	add_subdirectory(userspace/sdjagent)
	add_subdirectory(userspace/sdchecks)
	add_subdirectory(scripts)
	add_subdirectory(test)
	add_subdirectory(bench)
	add_subdirectory(docker)
endif()

add_custom_target(run-unit-tests
	COMMAND $(MAKE) run-unit-test-testhelpers
	COMMAND $(MAKE) run-unit-test-dragent
	COMMAND $(MAKE) run-unit-test-libsanalyzer
)

install(PROGRAMS ${DRAIOS_DEPENDENCIES_DIR}/statsite-private-${STATSITE_VERSION}/statsite
	DESTINATION ${CMAKE_INSTALL_PREFIX}/bin
	COMPONENT agent-slim)

install(PROGRAMS ${PROJECT_SOURCE_DIR}/../sysdig/scripts/sysdig-probe-loader
	DESTINATION ${CMAKE_INSTALL_PREFIX}/bin
	RENAME sysdigcloud-probe-loader
	COMPONENT agent-slim)

install(PROGRAMS ${PROJECT_SOURCE_DIR}/scripts/gen-support-bundle
	DESTINATION ${CMAKE_INSTALL_PREFIX}/bin
	COMPONENT agent-slim)

if (NOT DEFINED COMBINED_PACKAGE)
    set(COMBINED_PACKAGE ON)
endif()

if (COMBINED_PACKAGE STREQUAL "ON")
    set(CPACK_COMPONENT_AGENT-SLIM_GROUP agent)
    set(CPACK_COMPONENT_AGENT-KMODULE_GROUP agent)
    set(CPACK_COMPONENTS_GROUPING ONE_PER_GROUP)
endif()

set(CPACK_PACKAGE_NAME "draios")
set(CPACK_PACKAGE_VENDOR "Sysdig Inc.")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Sysdig Agent")
set(CPACK_PACKAGE_VERSION "${AGENT_VERSION}")
if (DEFINED AGENT_BUILD_COMMIT)
    set(CPACK_PACKAGE_VERSION_PATCH "${AGENT_BUILD_COMMIT}")
endif()
set(CPACK_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}-${CMAKE_SYSTEM_PROCESSOR}")
set(CPACK_PACKAGE_DESCRIPTION_FILE "${PROJECT_SOURCE_DIR}/description.txt")
set(CPACK_PROJECT_CONFIG_FILE "${PROJECT_SOURCE_DIR}/CMakeCPackOptions.cmake")
set(CPACK_PACKAGE_RELOCATABLE "OFF")
set(CPACK_DRAIOS_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}")

if(PACKAGE_DEB_ONLY STREQUAL "ON")
  set(CPACK_GENERATOR DEB)
else()
  set(CPACK_GENERATOR DEB RPM TGZ)
endif()

set(CPACK_DEB_COMPONENT_INSTALL "ON")
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "Sysdig <support@sysdig.com>")
set(CPACK_DEBIAN_PACKAGE_SECTION "utils")
set(CPACK_DEBIAN_PACKAGE_HOMEPAGE "http://www.sysdig.com")
set(CPACK_DEBIAN_AGENT-SLIM_PACKAGE_DEPENDS "python")
set(CPACK_DEBIAN_AGENT-KMODULE_PACKAGE_DEPENDS "dkms (>= 2.1.0.0)")
set(CPACK_DEBIAN_AGENT_PACKAGE_DEPENDS "dkms (>= 2.1.0.0), python")
set(CPACK_DEBIAN_PACKAGE_CONTROL_EXTRA "${CMAKE_BINARY_DIR}/scripts/debian/postinst;${CMAKE_BINARY_DIR}/scripts/debian/prerm;${PROJECT_SOURCE_DIR}/scripts/debian/postrm")

set(CPACK_RPM_COMPONENT_INSTALL "ON")
set(CPACK_RPM_agent-slim_PACKAGE_REQUIRES "python")
set(CPACK_RPM_agent-slim_POST_INSTALL_SCRIPT_FILE "${PROJECT_SOURCE_DIR}/scripts/rpm/postinstall.slim")
set(CPACK_RPM_agent-slim_PRE_UNINSTALL_SCRIPT_FILE "${PROJECT_SOURCE_DIR}/scripts/rpm/preuninstall.slim")
set(CPACK_RPM_agent-slim_POST_UNINSTALL_SCRIPT_FILE "${PROJECT_SOURCE_DIR}/scripts/rpm/postuninstall")

set(CPACK_RPM_agent-kmodule_PACKAGE_REQUIRES "dkms, gcc, make, kernel-devel, perl")
set(CPACK_RPM_agent-kmodule_POST_INSTALL_SCRIPT_FILE "${PROJECT_SOURCE_DIR}/scripts/rpm/postinstall.kmodule")
set(CPACK_RPM_agent-kmodule_PRE_UNINSTALL_SCRIPT_FILE "${PROJECT_SOURCE_DIR}/scripts/rpm/preuninstall.kmodule")

set(CPACK_RPM_agent_PACKAGE_REQUIRES "dkms, gcc, make, kernel-devel, perl, python")
set(CPACK_RPM_agent_POST_INSTALL_SCRIPT_FILE "${PROJECT_SOURCE_DIR}/scripts/rpm/postinstall")
set(CPACK_RPM_agent_PRE_UNINSTALL_SCRIPT_FILE "${PROJECT_SOURCE_DIR}/scripts/rpm/preuninstall")
set(CPACK_RPM_agent_POST_UNINSTALL_SCRIPT_FILE "${PROJECT_SOURCE_DIR}/scripts/rpm/postuninstall")

set(CPACK_RPM_EXCLUDE_FROM_AUTO_FILELIST_ADDITION
	/etc/rc.d
	/etc/rc.d/init.d
	${CMAKE_INSTALL_PREFIX})
set(CPACK_RPM_PACKAGE_AUTOREQPROV " no")
set(CPACK_RPM_SPEC_MORE_DEFINE "%global __os_install_post %(echo '%{__os_install_post}' | sed -e 's!/usr/lib[^[:space:]]*/brp-python-bytecompile[[:space:]].*$!!g')")
set(CPACK_RPM_PACKAGE_RELOCATABLE "ON")
set(CPACK_RPM_RELOCATION_PATHS ${CMAKE_INSTALL_PREFIX})

set(CPACK_ARCHIVE_COMPONENT_INSTALL "ON")

include(CPack)
