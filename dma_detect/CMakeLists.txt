# dma_detect/CMakeLists.txt
# Builds hk_dma_detect as a static library, selecting the platform backend
# matching the build host.
#
# Backend layout mirrors platform/ and attestation/:
#   backends/win/PcieEnumWin.cpp     — Windows (SetupAPI + KDP registry)
#   backends/linux/PcieEnumLinux.cpp — Linux (sysfs + /proc/iomem)
#   backends/macos/PcieEnumMacOS_stub.cpp — macOS stub (IOKit path is a later phase)
#
# DMA / peripheral-hardware-trust forensics (catalog signals 127-135) add a sibling
# per-host backend set under backends/<os>/ plus the platform-clean aggregator
# src/forensics_report.cpp. They are gated behind HORKOS_DMA_FORENSICS so the base
# DMA-attack detection (hk_dma_scan) still builds where forensics are unwanted.

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

# ---- DMA / peripheral-hardware-trust forensics (signals 127-135) ------------
# Default ON on Win/Linux; ON on macOS too but the IOKit backends degrade where
# IOKit config reads are restricted (impl-plan §Build wiring). The platform-clean
# aggregator (forensics_report.cpp) compiles always when the option is ON; the
# per-OS forensic backends compile only on their matching host.
option(HORKOS_DMA_FORENSICS
    "Build the DMA/peripheral-hardware-trust forensic sensors (catalog 127-135)"
    ON)

set(dma_forensics_sources)
if(HORKOS_DMA_FORENSICS)
    list(APPEND dma_forensics_sources src/forensics_report.cpp)
    if(WIN32)
        list(APPEND dma_forensics_sources
            backends/win/ConfigSpaceForensics.cpp   # 127/128 + hk_dma_forensics_scan
            backends/win/MsixForensics.cpp           # 129
            backends/win/OptionRomForensics.cpp      # 130
            backends/win/BarProfile.cpp              # 131
            backends/win/TlpLatencyProbe.cpp         # 132
            backends/win/AcsTopology.cpp             # 133
            backends/win/HotplugMonitor.cpp          # 134 (subscribe)
            backends/win/IommuFaultEtw.cpp)          # 135 (ETW consumer; HK-UNCERTAIN)
    elseif(UNIX AND NOT APPLE)
        list(APPEND dma_forensics_sources
            backends/linux/ConfigSpaceForensics.cpp  # 127/128 + hk_dma_forensics_scan
            backends/linux/MsixForensics.cpp         # 129
            backends/linux/OptionRomForensics.cpp    # 130
            backends/linux/BarProfile.cpp            # 131
            backends/linux/TlpLatencyProbe.cpp       # 132
            backends/linux/AcsTopology.cpp           # 133
            backends/linux/HotplugMonitor.cpp)       # 134 (subscribe)
            # 135 Linux arm is the eBPF program kernel/linux/bpf/src/iommu_fault.bpf.c
            # (built by kernel/linux/bpf, gated by HORKOS_LINUX_EBPF), NOT a userspace TU.
    elseif(APPLE)
        list(APPEND dma_forensics_sources
            backends/macos/ConfigSpaceForensics.mm   # 127/128 + hk_dma_forensics_scan
            backends/macos/MsixForensics.mm          # 129
            backends/macos/OptionRomForensics.mm     # 130
            backends/macos/BarProfile.mm             # 131
            backends/macos/AcsTopology.mm)           # 133
            # macOS hot-plug (134) / TLP (132) / IOMMU-fault (135) arms land with the
            # IOKit notification + side-channel work in a later phase.
    endif()
endif()

# src/page_hash.c — platform-free page-hash helper shared with the host
# thread-provenance enrichment plane (signal 24 module-stomp / module-path id).
# Pure C99, no platform headers — compiles on every host backend.
add_library(hk_dma_detect STATIC
    ${dma_detect_backend}
    src/page_hash.c
    ${dma_forensics_sources})

target_include_directories(hk_dma_detect PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# Windows: link SetupAPI and cfgmgr32 (also declared via #pragma comment in
# the source, but explicit here so CMake consumers get the dependency without
# touching the source pragma).
if(WIN32)
    target_link_libraries(hk_dma_detect PRIVATE setupapi cfgmgr32)
endif()

# macOS: the forensic backends are Objective-C++ (.mm) over IOKit; link the
# IOKit + CoreFoundation frameworks (impl-plan §Build wiring).
if(APPLE AND HORKOS_DMA_FORENSICS)
    target_link_libraries(hk_dma_detect PRIVATE
        "-framework IOKit"
        "-framework CoreFoundation")
endif()

# Consumers: link hk_dma_detect, then call hk_dma_scan() from horkos/dma_detect.h,
# and (when HORKOS_DMA_FORENSICS) hk_dma_forensics_scan() from horkos/dma_forensics.h.
