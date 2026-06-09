# kernel/linux/lkm/CMakeLists.txt
# Role: CMake integration for the out-of-tree Linux LKM.
#       Exposes HORKOS_LINUX_LKM option; when ON, adds a custom target that
#       drives the Kbuild Makefile in this directory. The module (horkos.ko) is a
#       multi-object build: horkos_main.o (exec tracepoint) + module_crc.o
#       (signal-95 read-only module-CRC debugfs export). Sources are listed in
#       the Kbuild Makefile, not here.
# Target platform: Linux (LKM non-Deck path).
# Interface: Consumed by kernel/linux/CMakeLists.txt (or the top-level CMake)
#            via add_subdirectory() when building for Linux.

cmake_minimum_required(VERSION 3.22)

# --------------------------------------------------------------------------
# Guard: this subdirectory must only be processed on Linux.
# Raw __linux__ ifdefs are prohibited (guardrail #1); CMake-level platform
# detection is the correct alternative.
# --------------------------------------------------------------------------
if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
    message(STATUS "horkos LKM: skipping (not a Linux host/cross build)")
    return()
endif()

# --------------------------------------------------------------------------
# Option
# --------------------------------------------------------------------------
option(HORKOS_LINUX_LKM
    "Build the Linux LKM (out-of-tree Kbuild module, non-Deck path)"
    OFF)

if(NOT HORKOS_LINUX_LKM)
    message(STATUS "horkos LKM: HORKOS_LINUX_LKM=OFF, target not added")
    return()
endif()

# --------------------------------------------------------------------------
# Resolve the kernel build directory.
# KDIR can be overridden on the cmake command line:
#   cmake -DHORKOS_LINUX_LKM=ON -DHORKOS_KDIR=/path/to/kernel/build ...
# --------------------------------------------------------------------------
if(NOT DEFINED HORKOS_KDIR)
    execute_process(
        COMMAND uname -r
        OUTPUT_VARIABLE _kernel_release
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    set(HORKOS_KDIR "/lib/modules/${_kernel_release}/build"
        CACHE PATH "Kernel build directory for out-of-tree module")
endif()

message(STATUS "horkos LKM: KDIR=${HORKOS_KDIR}")

# --------------------------------------------------------------------------
# Custom target: horkos_lkm
# Invokes the Kbuild Makefile in this source directory.
# The BYPRODUCTS list tells Ninja/make about the .ko artefact so incremental
# builds know when to re-link.
# --------------------------------------------------------------------------
set(_lkm_source_dir "${CMAKE_CURRENT_SOURCE_DIR}")
set(_lkm_ko         "${_lkm_source_dir}/horkos.ko")

add_custom_target(horkos_lkm ALL
    COMMAND ${CMAKE_MAKE_PROGRAM}
            -C "${HORKOS_KDIR}"
            M="${_lkm_source_dir}"
            modules
    BYPRODUCTS "${_lkm_ko}"
    WORKING_DIRECTORY "${_lkm_source_dir}"
    COMMENT "Building horkos LKM against ${HORKOS_KDIR}"
    VERBATIM
)

# --------------------------------------------------------------------------
# Companion clean target (not wired to CMake's built-in clean because Kbuild
# manages its own artefacts; run manually with: cmake --build . --target horkos_lkm_clean)
# --------------------------------------------------------------------------
add_custom_target(horkos_lkm_clean
    COMMAND ${CMAKE_MAKE_PROGRAM}
            -C "${HORKOS_KDIR}"
            M="${_lkm_source_dir}"
            clean
    WORKING_DIRECTORY "${_lkm_source_dir}"
    COMMENT "Cleaning horkos LKM build artefacts"
    VERBATIM
)
