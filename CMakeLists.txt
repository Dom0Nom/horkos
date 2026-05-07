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
# Windows kernel driver (Phase 3 — requires WDK)
# -------------------------------------------------------------------------
if(WIN32)
    add_subdirectory(kernel/win)
endif()

# -------------------------------------------------------------------------
# Tests
# -------------------------------------------------------------------------
enable_testing()
add_subdirectory(tests)
