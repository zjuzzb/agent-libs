cmake_minimum_required(VERSION 2.6)

project(draios)

# Versions of all third-party libraries used. These may be referred to
# in lower CMakeLists.txt files.
set(DRAIOS_OPENSSL_VERSION "1.0.2n")
set(DRAIOS_PROTOBUF_VERSION "3.5.0")
if(NOT CYGWIN)
set(DRAIOS_ZLIB_VERSION "1.2.11")
else()
set(DRAIOS_ZLIB_VERSION "1.2.8")
endif()
set(DRAIOS_POCO_VERSION "1.7.7-all")
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

set(DRAIOS_DEBUG_FLAGS "-D_DEBUG")
#set(DRAIOS_FEATURE_FLAGS "-DPPM_ENABLE_SENTINEL")

set(CMAKE_C_FLAGS "-Wall -ggdb -std=gnu11 ${DRAIOS_FEATURE_FLAGS}")
set(CMAKE_CXX_FLAGS "-Wall -ggdb --std=c++0x ${DRAIOS_FEATURE_FLAGS}")
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

set(DRAIOS_BIN_PREFIX "/opt/draios")

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
	set(KBUILD_FLAGS "${DRAIOS_DEBUG_FLAGS} ${DRAIOS_FEATURE_FLAGS}")
else()
	set(KBUILD_FLAGS "${DRAIOS_FEATURE_FLAGS}")
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
else()
	set(LUAJIT_INCLUDE "${DRAIOS_DEPENDENCIES_DIR}/LuaJIT-2.0.5/src")
	set(LUALIB "${LUAJIT_INCLUDE}/libluajit.a")
	set(WIN_HAL_INCLUDE "${DRAGENT_WINHAL_DIR}/target/include")
	set(WIN_HAL_LIB "${DRAGENT_WINHAL_DIR}/target/lib")
endif()

set(LPEG_LIB "${DRAIOS_DEPENDENCIES_DIR}/lpeg-1.0.0/target/lpeg.a")
set(LYAML_LIB "${DRAIOS_DEPENDENCIES_DIR}/lyaml-release-v6.0/target/lib/lua/5.1/yaml.a")
set(LIBYAML_LIB "${DRAIOS_DEPENDENCIES_DIR}/libyaml-0.1.7/target/lib/libyaml.a")
set(FALCO_SINSP_LIBRARY sanalyzer)
set(FALCO_SHARE_DIR "${DRAIOS_BIN_PREFIX}/share")
set(FALCO_ABSOLUTE_SHARE_DIR "${FALCO_SHARE_DIR}")
set(FALCO_COMPONENT agent)
add_subdirectory(${PROJECT_SOURCE_DIR}/../falco/userspace/engine ${PROJECT_BINARY_DIR}/userspace/engine)

add_subdirectory(${PROJECT_SOURCE_DIR}/../sysdig/userspace/libscap ${PROJECT_BINARY_DIR}/libscap)
if(NOT CYGWIN)
	add_subdirectory(userspace/cointerface)
endif()
add_subdirectory(userspace/comp_modules)
add_subdirectory(userspace/dragent)
add_subdirectory(userspace/draiosproto)
add_subdirectory(userspace/libsanalyzer)
if(NOT CYGWIN)
	add_subdirectory(userspace/sdjagent)
	add_subdirectory(userspace/sdchecks)
	add_subdirectory(scripts)
	add_subdirectory(test)
	add_subdirectory(docker)
endif()

install(PROGRAMS ${DRAIOS_DEPENDENCIES_DIR}/statsite-private-${STATSITE_VERSION}/statsite
	DESTINATION ${DRAIOS_BIN_PREFIX}/bin
	COMPONENT agent)

install(PROGRAMS ${PROJECT_SOURCE_DIR}/../sysdig/scripts/sysdig-probe-loader
	DESTINATION ${DRAIOS_BIN_PREFIX}/bin
	RENAME sysdigcloud-probe-loader
	COMPONENT agent)

install(PROGRAMS ${PROJECT_SOURCE_DIR}/scripts/gen-support-bundle
	DESTINATION ${DRAIOS_BIN_PREFIX}/bin
	COMPONENT agent)

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
set(CPACK_STRIP_FILES "ON")
set(CPACK_PACKAGE_RELOCATABLE "OFF")

if(PACKAGE_DEB_ONLY STREQUAL "ON")
  set(CPACK_GENERATOR DEB)
else()
  set(CPACK_GENERATOR DEB RPM TGZ)
endif()

set(CPACK_DEB_COMPONENT_INSTALL "ON")
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "Sysdig <support@sysdig.com>")
set(CPACK_DEBIAN_PACKAGE_SECTION "utils")
set(CPACK_DEBIAN_PACKAGE_HOMEPAGE "http://www.sysdig.com")
set(CPACK_DEBIAN_PACKAGE_DEPENDS "dkms (>= 2.1.0.0), python")
set(CPACK_DEBIAN_PACKAGE_CONTROL_EXTRA "${CMAKE_BINARY_DIR}/scripts/debian/postinst;${CMAKE_BINARY_DIR}/scripts/debian/prerm;${PROJECT_SOURCE_DIR}/scripts/debian/postrm")

set(CPACK_RPM_COMPONENT_INSTALL "ON")
set(CPACK_RPM_PACKAGE_REQUIRES "dkms, gcc, make, kernel-devel, perl, python")
set(CPACK_RPM_POST_INSTALL_SCRIPT_FILE "${PROJECT_SOURCE_DIR}/scripts/rpm/postinstall")
set(CPACK_RPM_PRE_UNINSTALL_SCRIPT_FILE "${PROJECT_SOURCE_DIR}/scripts/rpm/preuninstall")
set(CPACK_RPM_POST_UNINSTALL_SCRIPT_FILE "${PROJECT_SOURCE_DIR}/scripts/rpm/postuninstall")
set(CPACK_RPM_EXCLUDE_FROM_AUTO_FILELIST_ADDITION
	/etc/rc.d
	/etc/rc.d/init.d
	/opt)
set(CPACK_RPM_PACKAGE_AUTOREQPROV " no")
set(CPACK_RPM_SPEC_MORE_DEFINE "%global __os_install_post %(echo '%{__os_install_post}' | sed -e 's!/usr/lib[^[:space:]]*/brp-python-bytecompile[[:space:]].*$!!g')")
set(CPACK_ARCHIVE_COMPONENT_INSTALL "ON")
set(CPACK_RPM_PACKAGE_RELOCATABLE "OFF")

include(CPack)
