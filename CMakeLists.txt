cmake_minimum_required(VERSION 3.20)
project(horkos LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# Export compile commands for IDE / clangd support.
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# -------------------------------------------------------------------------
# hk_platform — platform abstraction layer
# Only the backend matching the current host is compiled.
# -------------------------------------------------------------------------
if(WIN32)
    set(hk_platform_src platform/platform_win.cpp)
elseif(APPLE)
    set(hk_platform_src platform/platform_macos.cpp)
elseif(UNIX)
    set(hk_platform_src platform/platform_linux.cpp)
else()
    message(FATAL_ERROR "Unsupported platform")
endif()

add_library(hk_platform STATIC ${hk_platform_src})
target_include_directories(hk_platform PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/platform
    ${CMAKE_CURRENT_SOURCE_DIR}/sdk/include
)

# The timing-side-channels clock seam (rdtscp_aux / pin_thread_to_core, signal 156)
# uses pthread_setaffinity_np on POSIX; link the threading library so any consumer of
# hk_platform resolves it.
find_package(Threads REQUIRED)
target_link_libraries(hk_platform PUBLIC Threads::Threads)

# macos-codesign-integrity: the macOS backend's signal-124 trust reads
# (read_boot_args via IORegistry; csr_*/SIP) pull CoreFoundation + IOKit. Link
# them on APPLE so any consumer of hk_platform (e.g. horkosd) resolves them.
if(APPLE)
    target_link_libraries(hk_platform PUBLIC
        "-framework CoreFoundation"
        "-framework IOKit"
    )
endif()

# -------------------------------------------------------------------------
# hk_attestation — attestation interface + backend stubs
# -------------------------------------------------------------------------
add_subdirectory(attestation)

# -------------------------------------------------------------------------
# hk_drm — DRM interface stub
# -------------------------------------------------------------------------
add_subdirectory(drm)

# -------------------------------------------------------------------------
# hk_ac — AC interface stub
# -------------------------------------------------------------------------
add_subdirectory(ac)

# -------------------------------------------------------------------------
# hk_sdk — public SDK static library + example (Phase 3)
# Platform-neutral; driver probe backend selected per host inside sdk/.
# -------------------------------------------------------------------------
add_subdirectory(sdk)
add_subdirectory(examples)

# -------------------------------------------------------------------------
# hk_dma_detect — Phase 4 Step 4.6 DMA-attack detection (detect-only)
# Backend selected by host platform; macOS ships a stub pending IOKit path.
# -------------------------------------------------------------------------
add_subdirectory(dma_detect)

# -------------------------------------------------------------------------
# Windows kernel driver (Phase 3 — requires WDK)
# -------------------------------------------------------------------------
if(WIN32)
    add_subdirectory(kernel/win)
endif()

# -------------------------------------------------------------------------
# Platform-specific components
# -------------------------------------------------------------------------
if(APPLE)
    # launchd/XPC daemon bring-up skeleton.
    add_subdirectory(daemon/macos)
    # EndpointSecurity client (self-gates on HORKOS_MACOS_ES).
    add_subdirectory(kernel/macos/es)
elseif(UNIX)
    add_subdirectory(kernel/linux)
endif()
