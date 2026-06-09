# bypass-tests/dma_hardware/CMakeLists.txt
# DMA / peripheral-hardware-trust bypass-test merge gate (guardrail #12). One test
# per catalog signal 127-135. Unlike the platform kernel gates, these fixtures are
# HOST-RUNNABLE today: each compiles the platform-clean aggregator TU
# (dma_detect/src/forensics_report.cpp) directly and asserts the REAL containment /
# OUI / aliasing / structural-gate / serialization decision functions — the same
# helpers the server scoring path (server/telemetry/src/dma_forensics.rs) pins
# against. Both the detection (positive) and the FP-suppression (negative) halves
# are load-bearing assertions that run now.
#
# The live-HARDWARE halves (option-ROM enable/read 130, udev/CM/IOKit hot-plug 134,
# eBPF/ETW IOMMU faults 135) are gated behind per-test HK_DMA_*_TEST_ENABLED defines
# and only fill in on the real toolchain / on-box; the structural + flag-packing
# assertions for those signals still execute on the host.
#
# This subdirectory is added UNCONDITIONALLY by the root CMakeLists (like dma_detect
# itself) because the helpers it tests carry no platform API and build on every host.

set(HK_DMA_BYPASS_TESTS
    bypass_dsn_clone            # signal 127
    bypass_extcfg_alias         # signal 128
    bypass_msix_overflow        # signal 129
    bypass_rom_identity         # signal 130
    bypass_bar_geometry         # signal 131
    bypass_latency_only         # signal 132 (never-standalone gate)
    bypass_acs_p2p              # signal 133
    bypass_hotplug_after_start  # signal 134
    bypass_iommu_fault_storm)   # signal 135

foreach(_t IN LISTS HK_DMA_BYPASS_TESTS)
    add_executable(hk_${_t}
        ${_t}.cpp
        ${CMAKE_SOURCE_DIR}/dma_detect/src/forensics_report.cpp)
    target_include_directories(hk_${_t} PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/dma_detect/include)
    add_test(NAME hk_${_t} COMMAND hk_${_t})
endforeach()
