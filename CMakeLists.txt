cmake_minimum_required(VERSION 2.6)

project(draios)

set(DRAIOS_DEBUG_FLAGS "-D_DEBUG")
#set(DRAIOS_FEATURE_FLAGS "-DPPM_ENABLE_SENTINEL")

set(CMAKE_C_FLAGS "-Wall -ggdb ${DRAIOS_FEATURE_FLAGS}")
set(CMAKE_CXX_FLAGS "-Wall -ggdb --std=c++0x ${DRAIOS_FEATURE_FLAGS}")
set(CMAKE_C_FLAGS_DEBUG "${DRAIOS_DEBUG_FLAGS}")
set(CMAKE_CXX_FLAGS_DEBUG "${DRAIOS_DEBUG_FLAGS}")
set(CMAKE_C_FLAGS_RELEASE "-O3 -fno-strict-aliasing -DNDEBUG")
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -fno-strict-aliasing -DNDEBUG")

add_definitions(-DPLATFORM_NAME="${CMAKE_SYSTEM_NAME}")
add_definitions(-DHAS_CAPTURE)

set(DRAIOS_BIN_PREFIX "/opt/draios")

set(ZLIB_INCLUDE "${DRAIOS_DEPENDENCIES_DIR}/zlib-1.2.8")
set(ZLIB_LIB "${DRAIOS_DEPENDENCIES_DIR}/zlib-1.2.8/libz.a")
add_subdirectory(${PROJECT_SOURCE_DIR}/../sysdig/userspace/libscap ${PROJECT_BINARY_DIR}/libscap)
add_subdirectory(userspace/dragent)
add_subdirectory(userspace/libsanalyzer)
add_subdirectory(userspace/sdjagent)
add_subdirectory(test)

set(CPACK_PACKAGE_NAME "draios")
set(CPACK_PACKAGE_VENDOR "Draios Inc.")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Draios agent")
set(CPACK_PACKAGE_VERSION "${AGENT_VERSION}")
set(CPACK_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}-${CMAKE_SYSTEM_PROCESSOR}")
set(CPACK_PACKAGE_DESCRIPTION_FILE "${PROJECT_SOURCE_DIR}/description.txt")
set(CPACK_PROJECT_CONFIG_FILE "${PROJECT_SOURCE_DIR}/CMakeCPackOptions.cmake")
set(CPACK_STRIP_FILES "ON")

set(CPACK_GENERATOR DEB RPM TGZ)

set(CPACK_DEB_COMPONENT_INSTALL "ON")
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "Draios Inc. <support@draios.com>")
set(CPACK_DEBIAN_PACKAGE_SECTION "utils")
set(CPACK_DEBIAN_PACKAGE_HOMEPAGE "http://www.draios.com")
set(CPACK_DEBIAN_PACKAGE_DEPENDS "sysdig (>= ${SYSDIG_MINIMUM_VERSION})")
set(CPACK_DEBIAN_PACKAGE_CONTROL_EXTRA "${PROJECT_SOURCE_DIR}/scripts/debian/postinst;${PROJECT_SOURCE_DIR}/scripts/debian/prerm;${PROJECT_SOURCE_DIR}/scripts/debian/postrm")

set(CPACK_RPM_COMPONENT_INSTALL "ON")
set(CPACK_RPM_PACKAGE_REQUIRES "sysdig >= ${SYSDIG_MINIMUM_VERSION}, gcc, make, kernel-devel, perl")
set(CPACK_RPM_POST_INSTALL_SCRIPT_FILE "${PROJECT_SOURCE_DIR}/scripts/rpm/postinstall")
set(CPACK_RPM_PRE_UNINSTALL_SCRIPT_FILE "${PROJECT_SOURCE_DIR}/scripts/rpm/preuninstall")
set(CPACK_RPM_POST_UNINSTALL_SCRIPT_FILE "${PROJECT_SOURCE_DIR}/scripts/rpm/postuninstall")
set(CPACK_RPM_EXCLUDE_FROM_AUTO_FILELIST_ADDITION
	/etc/rc.d
	/etc/rc.d/init.d
	/opt)
set(CPACK_RPM_PACKAGE_AUTOREQPROV " no")

set(CPACK_ARCHIVE_COMPONENT_INSTALL "ON")

include(CPack)
