cmake_minimum_required(VERSION 2.6)

project(draios)

option(BUILD_WARNINGS_AS_ERRORS "Enable building with -Wextra -Werror flags")

# Versions of all third-party libraries used. These may be referred to in lower CMakeLists.txt
# files.
set(DRAIOS_OPENSSL_VERSION "1.1.1h")
set(DRAIOS_PROTOBUF_VERSION "3.9.2")
if(NOT CYGWIN)
    set(DRAIOS_ZLIB_VERSION "1.2.11")
else()
    set(DRAIOS_ZLIB_VERSION "1.2.8")
endif()
set(DRAIOS_POCO_VERSION "1.9.0-all")
set(DRAIOS_GTEST_VERSION "1.7.0")
set(DRAIOS_YAML_VERSION "cpp-0.5.1")
set(DRAIOS_BOOST_VERSION "1_57_0")
set(DRAIOS_CURL_VERSION "7.61.0")
set(DRAIOS_JQ_VERSION "1.5")
set(DRAIOS_B64_VERSION "1.2")
set(DRAIOS_GRPC_VERSION "1.24.3")
set(DRAIOS_GPERFTOOLS_VERSION "2.5")
if(CYGWIN)
    set(DRAIOS_LUAJIT_VERSION "2.0.5")
else()
    set(DRAIOS_LUAJIT_VERSION "2.0.3")
endif()
set(DRAIOS_CARES_VERSION "1.13.0")
set(DRAIOS_KUBECTL_VERSION "1.11.10")
set(DRAIOS_LINUX_BENCH_VERSION "0.2.0.4")
set(DRAIOS_KUBE_BENCH_VERSION "0.2.8")
set(DRAIOS_STRING_VIEW_LITE_VERSION "1.4.0")
if(NOT CYGWIN)
    set(DRAIOS_TBB_VERSION "2018_U5")
endif()
set(DRAIOS_NJSON_VERSION "3.3.0")
set(DRAIOS_BENCHMARK_VERSION "1.5.0")

set(SPLIT_REPO TRUE)
set(LIBSINSP_DIR "${PROJECT_SOURCE_DIR}/../libsinsp/")
if(EXISTS "${PROJECT_SOURCE_DIR}/../libscap-hayabusa")
    # assume it's a hayabusa based build
    set(LIBSCAP_DIR "${PROJECT_SOURCE_DIR}/../libscap-hayabusa/")
else()
    set(LIBSCAP_DIR "${PROJECT_SOURCE_DIR}/../libscap/")
endif()

# Add path for custom CMake modules used to build dependencies from sysdig (libscap, libsinsp)
list(APPEND CMAKE_MODULE_PATH "${LIBSCAP_DIR}/cmake/modules")
list(APPEND CMAKE_MODULE_PATH "${LIBSINSP_DIR}/cmake/modules")

# Set up the different flavors of agent binaries
include(CMakeConfigurationTypes.cmake)

add_definitions(-DPLATFORM_NAME="${CMAKE_SYSTEM_NAME}")
add_definitions(-DHAS_CAPTURE)
if(CYGWIN)
    add_definitions(-DCYGWING_AGENT)
endif()

add_definitions(-D_GNU_SOURCE)

if(DEFINED ENV{CMAKE_INSTALL_PREFIX})
    set(CMAKE_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}")
endif()

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(KBUILD_FLAGS "${DRAIOS_DEBUG_FLAGS} ${DRAIOS_FEATURE_FLAGS}")
    set(CPACK_STRIP_FILES "OFF")
else()
    set(KBUILD_FLAGS "${DRAIOS_FEATURE_FLAGS}")
    set(CPACK_STRIP_FILES "ON")
endif()

set(GOPATH "${DRAIOS_DEPENDENCIES_DIR}/go")
set(GOENV
    scl
    enable
    sclo-git212
    --
    env
    GOPATH=${GOPATH}
    GO111MODULE=on
)

if(NOT CYGWIN)
    set(PROMSCRAPE_DIR "${DRAIOS_DEPENDENCIES_DIR}/promscrape")

    install(
        PROGRAMS ${PROMSCRAPE_DIR}/promscrape_v1 ${PROMSCRAPE_DIR}/promscrape_v2
        DESTINATION ${CMAKE_INSTALL_PREFIX}/bin
        COMPONENT agent-slim
    )
endif()

set(PACKAGE_NAME "draios-agent")
set(PROBE_VERSION "${AGENT_VERSION}")
set(PROBE_NAME "sysdigcloud-probe")
set(PROBE_DEVICE_NAME "sysdigcloud")

if(NOT CYGWIN)
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
    set(CURL_INCLUDE_DIR "${DRAIOS_DEPENDENCIES_DIR}/curl-7.61.0/include")
    # Matches name actually used by falco CMakeLists.txt
    set(STRING_VIEW_LITE_INCLUDE
        "${DRAIOS_DEPENDENCIES_DIR}/string-view-lite-${DRAIOS_STRING_VIEW_LITE_VERSION}/include/"
    )
    set(TBB_INCLUDE_DIR "${DRAIOS_DEPENDENCIES_DIR}/tbb-${DRAIOS_TBB_VERSION}/include/")
else()
    set(LUAJIT_INCLUDE "${DRAIOS_DEPENDENCIES_DIR}/LuaJIT-2.0.5/src")
    set(LUALIB "${LUAJIT_INCLUDE}/libluajit.a")
    set(CURL_INCLUDE_DIR "${DRAIOS_DEPENDENCIES_DIR}/curl-7.61.0/include")
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

if(SPLIT_REPO)
    include(libscap)
else()
    include_directories(${ZLIB_INCLUDE})
    add_subdirectory(${PROJECT_SOURCE_DIR}/../sysdig/driver ${PROJECT_BINARY_DIR}/driver)
    add_subdirectory(
        ${PROJECT_SOURCE_DIR}/../sysdig/userspace/libscap ${PROJECT_BINARY_DIR}/libscap
    )
endif()

set(LIBSINSP_SOURCE_DIR ${LIBSINSP_DIR}/userspace/libsinsp)
set(LIBSINSP_INCLUDE_DIRS ${LIBSINSP_SOURCE_DIR} ${LIBSINSP_SOURCE_DIR}/../async
                          ${LIBSINSP_SOURCE_DIR}/third-party/jsoncpp
)

# This suppresses warnings where a project in add_dependencies() is missing. This happens for
# dependencies of falco engine, where the agent cmakefiles create the dependencies but don't create
# ExternalProjects for them.
cmake_policy(SET CMP0046 OLD)
include_directories(${LIBSCAP_INCLUDE_DIRS} ${LIBSINSP_INCLUDE_DIRS})
add_subdirectory(
    ${PROJECT_SOURCE_DIR}/../oss-falco/userspace/engine ${PROJECT_BINARY_DIR}/userspace/engine
)

if(NOT CYGWIN)
    add_subdirectory(userspace/cointerface)
endif()
add_subdirectory(userspace/command-line/src)
add_subdirectory(userspace/comp_modules)
add_subdirectory(userspace/dragent/src)
add_subdirectory(userspace/dragent/test_helpers)
add_subdirectory(userspace/draiosproto)
add_subdirectory(userspace/libsanalyzer/src)
add_subdirectory(userspace/librest/src)
add_subdirectory(userspace/userspace-shared/src)
add_subdirectory(userspace/userspace-shared/test-helpers)
add_subdirectory(userspace/agentone/src)
if(NOT CYGWIN)
    add_subdirectory(userspace/sdjagent)
    add_subdirectory(userspace/sdchecks)
    add_subdirectory(scripts)
    add_subdirectory(docker)
endif()

if(ADD_INTERNAL_TEST_TARGETS)
    include(CMakeListsForTest.cmake)
endif()

# The /test tests and associated test-helpers run in the release jenkins job. That uses the
# production (non-internal) build.
if(NOT CYGWIN)
    add_subdirectory(test)
endif()
add_subdirectory(userspace/test_helpers/src)
add_subdirectory(userspace/test_helpers/test)

install(
    PROGRAMS ${DRAIOS_DEPENDENCIES_DIR}/statsite-private-${STATSITE_VERSION}/statsite
    DESTINATION ${CMAKE_INSTALL_PREFIX}/bin
    COMPONENT agent-slim
)

install(
    PROGRAMS ${LIBSCAP_DIR}/scripts/sysdig-probe-loader
    DESTINATION ${CMAKE_INSTALL_PREFIX}/bin
    RENAME sysdigcloud-probe-loader
    COMPONENT agent-slim
)

install(
    PROGRAMS ${PROJECT_SOURCE_DIR}/scripts/gen-support-bundle
    DESTINATION ${CMAKE_INSTALL_PREFIX}/bin
    COMPONENT agent-slim
)
install(
    PROGRAMS ${PROJECT_SOURCE_DIR}/scripts/gen-support-bundle
    DESTINATION ${CMAKE_INSTALL_PREFIX}/bin
    COMPONENT agentone
)

if(NOT DEFINED COMBINED_PACKAGE)
    set(COMBINED_PACKAGE ON)
endif()

# So some quick notes on how everything happens at the interaction of CPack and CMake. From a 10k'
# level, each install command takes a component. CPack creates a package for each component. It also
# allows you to package multiple components together in the form of a group. The agent-slim is the
# former of these, and the regular agent, the latter.
#
# The grouping happens in the following CPACK_COMPONENT-<foo>-GROUP statements, which tells cpack
# the agent is a combination of the agent-slim and agent-kmodule components. For some ungodly
# reason, the component needs to be capitalized in some cpack variable names, but not in others
# (like the RPM ones below).
#
# Since we expect to package our distributables together, every bit which needs to be included in
# the final distributable needs to be in the same component or component group. While there is a way
# to specify dependencies on both the package and the components themselves, it's not clear exactly
# how this works, so if a bit needs to go in multiple distinct components, it needs to be installed
# twice (see the support bundle)
#
# Ultimately, cmake is run multiple times. The first time with COMBINED_PACKAGE off, which builds
# each component individually. This will ultimately produce the agent-slim, agentone, and
# agent-kmodule packages (among all others, technically). The second time, with COMBINED_PACKAGE on,
# which will produce the agent package. (Note: it may be possible to do this in a single run, but
# who knows)
#
# Below and in CMakeCPackOptions, there are extra rules per package/group/component. It's not clear
# why things are where they are.

if(COMBINED_PACKAGE STREQUAL "ON")
    set(CPACK_COMPONENT_AGENT-SLIM_GROUP agent)
    set(CPACK_COMPONENT_AGENT-KMODULE_GROUP agent)
    set(CPACK_COMPONENTS_GROUPING ONE_PER_GROUP)
endif()

set(CPACK_PACKAGE_NAME "draios")
set(CPACK_PACKAGE_VENDOR "Sysdig Inc.")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Sysdig Agent")
set(CPACK_PACKAGE_VERSION "${AGENT_VERSION}")
if(DEFINED AGENT_BUILD_COMMIT)
    set(CPACK_PACKAGE_VERSION_PATCH "${AGENT_BUILD_COMMIT}")
endif()
set(CPACK_PACKAGE_FILE_NAME
    "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}-${CMAKE_SYSTEM_PROCESSOR}"
)
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
set(CPACK_DEBIAN_AGENT-SLIM_PACKAGE_RECOMMENDS "python3")
set(CPACK_DEBIAN_AGENT-KMODULE_PACKAGE_DEPENDS "dkms (>= 2.1.0.0)")
set(CPACK_DEBIAN_AGENT_PACKAGE_DEPENDS "dkms (>= 2.1.0.0)")
set(CPACK_DEBIAN_AGENT_PACKAGE_RECOMMENDS "python3")
set(CPACK_DEBIAN_PACKAGE_CONTROL_EXTRA
    "${CMAKE_BINARY_DIR}/scripts/debian/postinst;${CMAKE_BINARY_DIR}/scripts/debian/prerm;${PROJECT_SOURCE_DIR}/scripts/debian/postrm"
)

set(CPACK_RPM_COMPONENT_INSTALL "ON")
set(CPACK_RPM_agent-slim_PACKAGE_SUGGESTS "python3")
set(CPACK_RPM_agent-slim_POST_INSTALL_SCRIPT_FILE
    "${PROJECT_SOURCE_DIR}/scripts/rpm/postinstall.slim"
)
set(CPACK_RPM_agent-slim_PRE_UNINSTALL_SCRIPT_FILE
    "${PROJECT_SOURCE_DIR}/scripts/rpm/preuninstall.slim"
)
set(CPACK_RPM_agent-slim_POST_UNINSTALL_SCRIPT_FILE
    "${PROJECT_SOURCE_DIR}/scripts/rpm/postuninstall"
)

set(CPACK_RPM_agent-kmodule_PACKAGE_REQUIRES "dkms, gcc, make, kernel-devel, perl")
set(CPACK_RPM_agent-kmodule_POST_INSTALL_SCRIPT_FILE
    "${PROJECT_SOURCE_DIR}/scripts/rpm/postinstall.kmodule"
)
set(CPACK_RPM_agent-kmodule_PRE_UNINSTALL_SCRIPT_FILE
    "${PROJECT_SOURCE_DIR}/scripts/rpm/preuninstall.kmodule"
)

set(CPACK_RPM_agent_PACKAGE_REQUIRES "dkms, gcc, make, kernel-devel, perl")
set(CPACK_RPM_agent_PACKAGE_SUGGESTS "python3")
set(CPACK_RPM_agent_POST_INSTALL_SCRIPT_FILE "${PROJECT_SOURCE_DIR}/scripts/rpm/postinstall")
set(CPACK_RPM_agent_PRE_UNINSTALL_SCRIPT_FILE "${PROJECT_SOURCE_DIR}/scripts/rpm/preuninstall")
set(CPACK_RPM_agent_POST_UNINSTALL_SCRIPT_FILE "${PROJECT_SOURCE_DIR}/scripts/rpm/postuninstall")

set(CPACK_RPM_agentone_POST_INSTALL_SCRIPT_FILE
    "${PROJECT_SOURCE_DIR}/scripts/rpm/postinstall.slim"
)
set(CPACK_RPM_agentone_PRE_INSTALL_SCRIPT_FILE "${PROJECT_SOURCE_DIR}/scripts/rpm/preinstall.slim")

set(CPACK_RPM_agentone_PRE_UNINSTALL_SCRIPT_FILE
    "${PROJECT_SOURCE_DIR}/scripts/rpm/preuninstall.slim"
)

set(CPACK_RPM_agentino_POST_INSTALL_SCRIPT_FILE
    "${PROJECT_SOURCE_DIR}/scripts/rpm/postinstall.slim"
)
set(CPACK_RPM_agentino_PRE_INSTALL_SCRIPT_FILE "${PROJECT_SOURCE_DIR}/scripts/rpm/preinstall.slim")

set(CPACK_RPM_agentino_PRE_UNINSTALL_SCRIPT_FILE
    "${PROJECT_SOURCE_DIR}/scripts/rpm/preuninstall.slim"
)

set(CPACK_RPM_EXCLUDE_FROM_AUTO_FILELIST_ADDITION /etc/rc.d /etc/rc.d/init.d
                                                  ${CMAKE_INSTALL_PREFIX}
)
set(CPACK_RPM_PACKAGE_AUTOREQPROV " no")
set(CPACK_RPM_SPEC_MORE_DEFINE
    "%global __os_install_post %(echo '%{__os_install_post}' | sed -e 's!/usr/lib[^[:space:]]*/brp-python-bytecompile[[:space:]].*$!!g')"
)
set(CPACK_RPM_PACKAGE_RELOCATABLE "ON")
set(CPACK_RPM_RELOCATION_PATHS ${CMAKE_INSTALL_PREFIX})

set(CPACK_ARCHIVE_COMPONENT_INSTALL "ON")

include(CPack)
