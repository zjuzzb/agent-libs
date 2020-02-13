
# We have 5 flavors of binaries:
# 1. Debug
# 2. Release
# 3. DebugInternal
# 4. ReleaseInternal
# 5. DebugInternalCodeCoverage
# Release builds are optimized and do not include debug symbols. Debug builds
# are non-optimized and do include debug symbols.
# Internal builds have special internal code in the production binaries and all
# unit test targets.

# Set the CMAKE option that lists the different flavors of binaries.
set(CMAKE_CONFIGURATION_TYPES "Debug;Release;DebugInternal;ReleaseInternal;DebugInternalCodeCoverage" CACHE STRING "" FORCE)

#set(DRAIOS_FEATURE_FLAGS "-DPPM_ENABLE_SENTINEL")
set(CMAKE_COMMON_FLAGS "-Wall -ggdb ${DRAIOS_FEATURE_FLAGS}")
if(BUILD_WARNINGS_AS_ERRORS)
	set(CMAKE_SUPPRESSED_WARNINGS "-Wno-unused-parameter -Wno-missing-field-initializers -Wno-sign-compare -Wno-type-limits")
	set(CMAKE_COMMON_FLAGS "${CMAKE_COMMON_FLAGS} -Wextra -Werror ${CMAKE_SUPPRESSED_WARNINGS}")
endif()
set(DRAIOS_DEBUG_FLAGS "-D_DEBUG")
set(CMAKE_C_FLAGS "-std=gnu11 ${CMAKE_COMMON_FLAGS}")
set(CMAKE_CXX_FLAGS "--std=c++0x ${CMAKE_COMMON_FLAGS}")

# Setup release build
# Add "-fno-inline -fno-omit-frame-pointer" for perf
set(CMAKE_C_FLAGS_RELEASE "-O3 -fno-strict-aliasing -DNDEBUG")
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -fno-strict-aliasing -DNDEBUG")

# Setup debug build
set(CMAKE_C_FLAGS_DEBUG "${DRAIOS_DEBUG_FLAGS}")
set(CMAKE_CXX_FLAGS_DEBUG "${DRAIOS_DEBUG_FLAGS}")

# Setup debug internal build
set(CMAKE_C_FLAGS_DEBUGINTERNAL "${CMAKE_C_FLAGS_DEBUG} -DFAULT_INJECTION_ENABLED")
set(CMAKE_CXX_FLAGS_DEBUGINTERNAL "${CMAKE_CXX_FLAGS_DEBUG} -DFAULT_INJECTION_ENABLED")
if(CMAKE_BUILD_TYPE STREQUAL "DebugInternal")
	# Tell dragent binaries to include special internal code.
	set(INCLUDE_INTERNAL_TEST_CODE 1)
	# Add special make targets which only exist for internal builds
	set(ADD_INTERNAL_TEST_TARGETS 1)
endif()

# Setup release internal build
# The release internal build is an optimized release build that includes
# features that only available for internal testing purposes.
set(CMAKE_C_FLAGS_RELEASEINTERNAL "${CMAKE_C_FLAGS_RELEASE} -DFAULT_INJECTION_ENABLED")
set(CMAKE_CXX_FLAGS_RELEASEINTERNAL "${CMAKE_CXX_FLAGS_RELEASE} -DFAULT_INJECTION_ENABLED")
if(CMAKE_BUILD_TYPE STREQUAL "ReleaseInternal")
	# Tell dragent binaries to include special internal code.
	set(INCLUDE_INTERNAL_TEST_CODE 1)
	# Add special make targets which only exist for internal builds
	set(ADD_INTERNAL_TEST_TARGETS 1)
endif()

# Setup debug internal code coverage build
set(CMAKE_C_FLAGS_DEBUGINTERNALCODECOVERAGE "${CMAKE_C_FLAGS_DEBUG} -fprofile-arcs -ftest-coverage -DFAULT_INJECTION_ENABLED")
set(CMAKE_CXX_FLAGS_DEBUGINTERNALCODECOVERAGE "${CMAKE_CXX_FLAGS_DEBUG} -fprofile-arcs -ftest-coverage -DFAULT_INJECTION_ENABLED")
if(CMAKE_BUILD_TYPE STREQUAL "DebugInternalCodeCoverage")
	set(RUN_UNIT_TEST_UNDER_CODE_COVERAGE 1)
	set(INCLUDE_INTERNAL_TEST_CODE 1)
	set(ADD_INTERNAL_TEST_TARGETS 1)
endif()
