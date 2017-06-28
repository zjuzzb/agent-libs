cmake_minimum_required(VERSION 2.6)

project(draios)

# Versions of all third-party libraries used. These may be referred to
# in lower CMakeLists.txt files.
set(DRAIOS_OPENSSL_VERSION "1.0.2j")
set(DRAIOS_PROTOBUF_VERSION "3.1.0")
set(DRAIOS_ZLIB_VERSION "1.2.8")
set(DRAIOS_POCO_VERSION "1.7.7-all")
set(DRAIOS_LIBSSH_VERSION "0.7.3")
set(DRAIOS_GTEST_VERSION "1.7.0")
set(DRAIOS_YAML_VERSION "cpp-0.5.1")
set(DRAIOS_BOOST_VERSION "1_57_0")
set(DRAIOS_CURL_VERSION "7.52.1")
set(DRAIOS_JQ_VERSION "1.5")
set(DRAIOS_B64_VERSION "1.2")
set(DRAIOS_GRPC_VERSION "1.1.4")
set(DRAIOS_GPERFTOOLS_VERSION "2.5")
set(DRAIOS_LUAJIT_VERSION "2.0.3")

set(DRAIOS_DEBUG_FLAGS "-D_DEBUG")
#set(DRAIOS_FEATURE_FLAGS "-DPPM_ENABLE_SENTINEL")

set(CMAKE_C_FLAGS "-Wall -ggdb -std=c11 ${DRAIOS_FEATURE_FLAGS}")
set(CMAKE_CXX_FLAGS "-Wall -ggdb --std=c++0x ${DRAIOS_FEATURE_FLAGS}")
set(CMAKE_C_FLAGS_DEBUG "${DRAIOS_DEBUG_FLAGS}")
set(CMAKE_CXX_FLAGS_DEBUG "${DRAIOS_DEBUG_FLAGS}")
# Add "-fno-inline -fno-omit-frame-pointer" for perf
set(CMAKE_C_FLAGS_RELEASE "-O3 -fno-strict-aliasing -DNDEBUG")
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -fno-strict-aliasing -DNDEBUG")

add_definitions(-DPLATFORM_NAME="${CMAKE_SYSTEM_NAME}")
add_definitions(-DHAS_CAPTURE)
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

add_subdirectory(${PROJECT_SOURCE_DIR}/../sysdig/driver ${PROJECT_BINARY_DIR}/driver)

set(ZLIB_INCLUDE "${DRAIOS_DEPENDENCIES_DIR}/zlib-1.2.8")
set(ZLIB_LIB "${DRAIOS_DEPENDENCIES_DIR}/zlib-1.2.8/libz.a")
add_custom_target(zlib)

if(EXISTS "${DRAIOS_DEPENDENCIES_DIR}/LuaJIT-2.0.3/src")
	set(LUAJIT_INCLUDE "${DRAIOS_DEPENDENCIES_DIR}/LuaJIT-2.0.3/src")
	set(LUALIB "${LUAJIT_INCLUDE}/libluajit.a")
else()
	set(LUAJIT_INCLUDE "${DRAIOS_DEPENDENCIES_DIR}/lua-5.1.5/src")
	set(LUALIB "${LUAJIT_INCLUDE}/liblua.a")
endif()
set(LPEG_LIB "${DRAIOS_DEPENDENCIES_DIR}/lpeg-1.0.0/target/lpeg.a")
set(LYAML_LIB "${DRAIOS_DEPENDENCIES_DIR}/lyaml-release-v6.0/target/lib/lua/5.1/yaml.a")
set(LIBYAML_LIB "${DRAIOS_DEPENDENCIES_DIR}/libyaml-0.1.4/target/lib/libyaml.a")
set(FALCO_SINSP_LIBRARY sanalyzer)
set(FALCO_SHARE_DIR "${DRAIOS_BIN_PREFIX}/share")
set(FALCO_COMPONENT agent)
set(FALCO_ETC_DIR "${DRAIOS_BIN_PREFIX}/etc")
set(FALCO_RULES_DEST_FILENAME "falco_rules.default.yaml")
add_subdirectory(${PROJECT_SOURCE_DIR}/../falco/userspace/engine ${PROJECT_BINARY_DIR}/userspace/engine)

add_subdirectory(${PROJECT_SOURCE_DIR}/../sysdig/userspace/libscap ${PROJECT_BINARY_DIR}/libscap)
add_subdirectory(userspace/cointerface)
add_subdirectory(userspace/dragent)
add_subdirectory(userspace/draiosproto)
add_subdirectory(userspace/libsanalyzer)
add_subdirectory(userspace/sdjagent)
add_subdirectory(userspace/sdchecks)
add_subdirectory(scripts)
add_subdirectory(test)

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
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Sysdig Cloud Agent")
set(CPACK_PACKAGE_VERSION "${AGENT_VERSION}")
set(CPACK_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}-${CMAKE_SYSTEM_PROCESSOR}")
set(CPACK_PACKAGE_DESCRIPTION_FILE "${PROJECT_SOURCE_DIR}/description.txt")
set(CPACK_PROJECT_CONFIG_FILE "${PROJECT_SOURCE_DIR}/CMakeCPackOptions.cmake")
set(CPACK_STRIP_FILES "ON")
set(CPACK_PACKAGE_RELOCATABLE "OFF")

set(CPACK_GENERATOR DEB RPM TGZ)

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
