# dma_detect/CMakeLists.txt
# Builds hk_dma_detect as a static library, selecting the platform backend
# matching the build host.  macOS does not have an equivalent sysfs or
# SetupAPI interface; a stub backend will be added when the macOS path lands.
#
# Backend layout mirrors platform/ and attestation/:
#   backends/win/PcieEnumWin.cpp     — Windows (SetupAPI + KDP registry)
#   backends/linux/PcieEnumLinux.cpp — Linux (sysfs + /proc/iomem)

cmake_minimum_required(VERSION 3.20)

if(WIN32)
    set(dma_detect_backend backends/win/PcieEnumWin.cpp)
elseif(UNIX AND NOT APPLE)
    set(dma_detect_backend backends/linux/PcieEnumLinux.cpp)
elseif(APPLE)
    # macOS stub: no sysfs equivalent; IOKit PCIe enumeration is a future phase.
    # The stub TU is committed at the path below (do not generate into the source
    # tree at configure time — that breaks read-only/out-of-source builds).
    set(dma_detect_backend backends/macos/PcieEnumMacOS_stub.cpp)
else()
    message(FATAL_ERROR "hk_dma_detect: unsupported platform")
endif()

add_library(hk_dma_detect STATIC ${dma_detect_backend})

target_include_directories(hk_dma_detect PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# Windows: link SetupAPI and cfgmgr32 (also declared via #pragma comment in
# the source, but explicit here so CMake consumers get the dependency without
# touching the source pragma).
if(WIN32)
    target_link_libraries(hk_dma_detect PRIVATE setupapi cfgmgr32)
endif()

# Consumers: link hk_dma_detect, then call hk_dma_scan() from horkos/dma_detect.h.
