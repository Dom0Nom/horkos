# bypass-tests/win/CMakeLists.txt
# Windows bypass-test merge gate (guardrail #12). Phase 3 builds the test in its
# disabled form; Phase 5 defines HK_BYOVD_TEST_ENABLED and adds the fixture.

add_executable(hk_bypass_byovd byovd_load.cpp)
target_include_directories(hk_bypass_byovd PRIVATE ${CMAKE_SOURCE_DIR}/sdk/include)
add_test(NAME hk_bypass_byovd COMMAND hk_bypass_byovd)

# win-kernel-object-callbacks self-integrity surface gate. Phase 3 builds it
# disabled (HK_SELFCHECK_TEST_ENABLED undefined); it activates when the kernel
# unhook fixture and the HK_EVENT_CALLBACK_* schema bump land. The enabled body
# also needs the kernel-private placeholder types from kernel/win/include, so
# that dir is on the include path for the activated build.
add_executable(hk_bypass_callback_unhook callback_unhook.cpp)
target_include_directories(hk_bypass_callback_unhook PRIVATE
    ${CMAKE_SOURCE_DIR}/sdk/include
    ${CMAKE_SOURCE_DIR}/kernel/win/include)
add_test(NAME hk_bypass_callback_unhook COMMAND hk_bypass_callback_unhook)

# win-kernel-thread-injection thread-origin gate. The live-fixture test ships
# DISABLED; the correlator-replay test runs on the host now (see its CMakeLists).
add_subdirectory(thread_origin)

# win-kernel-driver-integrity merge gate (guardrail #12). One bypass test per new
# kernel sensor under kernel/win/. Each ships DISABLED (HK_INTEGRITY_TEST_ENABLED
# undefined): a compiled no-op that passes, exactly like byovd_load.cpp; its
# assertions activate when the Phase-5 signed-fixture driver and the
# HK_EVENT_INTEGRITY_FINDING schema bump land. The enabled bodies need the
# kernel-private placeholder types from kernel/win/include, so that dir is on the
# include path for the activated build. The repo never commits a hooking driver.
set(HK_INTEGRITY_BYPASS_TESTS
    ssdt_hook_detect            # signal 35
    drvobj_fastio_detour        # signal 34
    ci_state_flip               # signal 30
    kdbg_attach                 # signal 33
    nonimage_exec_map           # signal 32
    callback_strip_sentinel)    # signal 31
foreach(_t IN LISTS HK_INTEGRITY_BYPASS_TESTS)
    add_executable(hk_bypass_${_t} ${_t}.cpp)
    target_include_directories(hk_bypass_${_t} PRIVATE
        ${CMAKE_SOURCE_DIR}/sdk/include
        ${CMAKE_SOURCE_DIR}/kernel/win/include)
    add_test(NAME hk_bypass_${_t} COMMAND hk_bypass_${_t})
endforeach()

# win-kernel-syscall-etw-integrity merge gate (guardrail #12). One bypass test per
# new kernel sensor (signals 208-216) under kernel/win/. Same DISABLED-but-compiled
# pattern: a no-op that passes until the Phase-5 signed-fixture driver and the
# HK_EVENT_INTEGRITY_FINDING schema bump land, then the assertions activate. The
# enabled bodies need the kernel-private placeholder types from kernel/win/include.
# The repo never commits a hooking/MSR-rewriting driver.
set(HK_SYSCALL_ETW_BYPASS_TESTS
    ssdt_entry_hook             # signal 208
    ssdt_base_swap              # signal 216
    lstar_repoint               # signal 210
    idt_pf_hook                 # signal 214
    syscall_prologue_patch      # signal 213
    etwti_teardown              # signal 212
    etw_session_disable         # signal 215
    infinity_hook_probe         # signal 211
    shadow_ssdt_hook)           # signal 209
foreach(_t IN LISTS HK_SYSCALL_ETW_BYPASS_TESTS)
    add_executable(hk_bypass_${_t} ${_t}.cpp)
    target_include_directories(hk_bypass_${_t} PRIVATE
        ${CMAKE_SOURCE_DIR}/sdk/include
        ${CMAKE_SOURCE_DIR}/kernel/win/include)
    add_test(NAME hk_bypass_${_t} COMMAND hk_bypass_${_t})
endforeach()

# win-usermode-overlay render/overlay-hook merge gate (guardrail #12). One bypass
# test per sensor group: overlay_vtable_swap covers the present-path provenance
# sensors (signals 46/47); external_overlay_window covers the window-scan sensors
# (signals 49/51). Both ship DISABLED (HK_RENDER_BYPASS_ENABLED undefined): a
# compiled no-op that passes, exactly like byovd_load.cpp. Their assertions
# activate when the render scoring/report path + SDK swapchain-pointer integration
# (plan R2) land. These are USERMODE-only fixtures (no WDK / kernel headers), so
# only sdk/include is on the include path. The repo never commits a real overlay
# binary.
set(HK_RENDER_BYPASS_TESTS
    overlay_vtable_swap         # signals 46/47
    external_overlay_window)    # signals 49/51
foreach(_t IN LISTS HK_RENDER_BYPASS_TESTS)
    add_executable(hk_bypass_${_t} ${_t}.cpp)
    target_include_directories(hk_bypass_${_t} PRIVATE
        ${CMAKE_SOURCE_DIR}/sdk/include)
    add_test(NAME hk_bypass_${_t} COMMAND hk_bypass_${_t})
endforeach()

# win-input-automation input-provenance merge gate (guardrail #12). One bypass test
# per sensor group: synthetic_input_provenance covers the raw-input/synthetic-artifact
# sensors (signals 55/63); input_filter_interloper covers the class-filter sensor
# (signal 56). Both ship DISABLED (HK_INPUT_BYPASS_ENABLED undefined): a compiled
# no-op that passes, exactly like byovd_load.cpp. Their assertions activate when the
# input scoring/report path + the SDK WM_INPUT/LL-hook stream integration and the
# class-filter signer-resolution pass land. These are USERMODE-only fixtures (no WDK /
# kernel headers), so only sdk/include is on the include path. The repo never commits
# a real injection tool or input-filter binary.
set(HK_INPUT_BYPASS_TESTS
    synthetic_input_provenance  # signals 55/63
    input_filter_interloper)    # signal 56
foreach(_t IN LISTS HK_INPUT_BYPASS_TESTS)
    add_executable(hk_bypass_${_t} ${_t}.cpp)
    target_include_directories(hk_bypass_${_t} PRIVATE
        ${CMAKE_SOURCE_DIR}/sdk/include)
    add_test(NAME hk_bypass_${_t} COMMAND hk_bypass_${_t})
endforeach()

# win-handle-memory-access external-memory-access merge gate (guardrail #12). One
# bypass test per sensor group (signals 64/66/71/72) plus a false-positive guard.
# All ship DISABLED (HK_VMWATCH_TEST_ENABLED undefined): a compiled no-op that passes,
# exactly like byovd_load.cpp. Their assertions activate when the Phase-5 PPL/ELAM
# ETW-TI VM consumer + the Ob post-op provenance emit + the HK_EVENT_VM_ACCESS /
# HANDLE_PROVENANCE / PROTECT_DRIFT schema bumps (incl. the HK_EVENT_PAYLOAD_MAX
# growth for the 28/24/20-byte payloads) land. The enabled bodies need the
# kernel-private placeholder types from kernel/win/include. The repo never commits an
# external memory-reader/writer or a handle-laundering tool.
set(HK_VMWATCH_BYPASS_TESTS
    vm_read_external        # signal 64 (remote ReadVm)
    vm_write_codecave       # signal 64 (remote write into +X section)
    handle_dup_launder      # signal 66
    protect_flip            # signal 71
    staging_sequence        # signal 72
    vmwatch_whitelist_fp)   # FP guard for 64/71 gating
foreach(_t IN LISTS HK_VMWATCH_BYPASS_TESTS)
    add_executable(hk_bypass_${_t} ${_t}.cpp)
    target_include_directories(hk_bypass_${_t} PRIVATE
        ${CMAKE_SOURCE_DIR}/sdk/include
        ${CMAKE_SOURCE_DIR}/kernel/win/include)
    add_test(NAME hk_bypass_${_t} COMMAND hk_bypass_${_t})
endforeach()

# hardware-input-devices USB/HID device-trust merge gate (guardrail #12, signals
# 136/137/143). One bypass test per sensor group: hid_descriptor_template_clone covers
# the HID structural-fingerprint sensor (136); usb_bridge_descriptor_spoof covers the
# descriptor-coherence (137) + composite-interface (143) sensors. Both ship DISABLED
# (HK_DEVICE_TRUST_BYPASS_ENABLED undefined): a compiled no-op that passes, exactly like
# byovd_load.cpp. Their assertions activate when the server fingerprint-corpus /
# descriptor-allowlist fusion path lands. These are USERMODE-only fixtures (no WDK /
# kernel headers); they include the pure device-trust cores under
# sdk/src/backends/win/input, so that backend dir is on the include path. The repo never
# commits a cloning firmware image or a bridge-spoof tool.
set(HK_DEVICE_TRUST_BYPASS_TESTS
    hid_descriptor_template_clone   # signal 136
    usb_bridge_descriptor_spoof)    # signals 137/143
foreach(_t IN LISTS HK_DEVICE_TRUST_BYPASS_TESTS)
    add_executable(hk_bypass_${_t} ${_t}.cpp)
    target_include_directories(hk_bypass_${_t} PRIVATE
        ${CMAKE_SOURCE_DIR}/sdk/include
        ${CMAKE_SOURCE_DIR}/sdk/src/backends/win)
    add_test(NAME hk_bypass_${_t} COMMAND hk_bypass_${_t})
endforeach()

# memory-integrity-selfcheck merge gate (guardrail #12, signals 145-153). One bypass
# test per sensor group: self_text_patch covers the kernel-corroborated cross-view /
# CoW / PTE sensors (145/146/152); self_iat_veh_hook covers the userspace-format
# IAT/VEH/TLS sensors (149/150/153) + the FP guard; self_hwbp covers the kernel-context
# DR audit (148). All ship DISABLED (HK_SELFCHECK_TEST_ENABLED undefined): a compiled
# no-op that passes, exactly like byovd_load.cpp. Their assertions activate when the
# Phase-5 signed fixture harness + the HK_IOCTL_SELF_READ_VA caller-identity gate + the
# large-record self-read drain plane + the server signed-overlay allow-list land. The
# enabled bodies need the wire types from sdk/include + the kernel-private mirrors from
# kernel/win/include. The repo never commits a real self-patch / IAT-hook / DR-spoof tool.
set(HK_SELFCHECK_BYPASS_TESTS
    self_text_patch       # signals 145/146/152
    self_iat_veh_hook     # signals 149/150/153 + FP guard
    self_hwbp)            # signal 148
foreach(_t IN LISTS HK_SELFCHECK_BYPASS_TESTS)
    add_executable(hk_bypass_${_t} ${_t}.cpp)
    target_include_directories(hk_bypass_${_t} PRIVATE
        ${CMAKE_SOURCE_DIR}/sdk/include
        ${CMAKE_SOURCE_DIR}/ac/include
        ${CMAKE_SOURCE_DIR}/kernel/win/include)
    add_test(NAME hk_bypass_${_t} COMMAND hk_bypass_${_t})
endforeach()

# behavioral-aim provenance/cadence merge gate (guardrail #12, signals 163/164/165/
# 171). One bypass test per sensor group: aim_injection_provenance covers the raw-HID
# provenance + quantization + injection sensors (163/164/171); aim_framelock_cadence
# covers the polling-interval-jitter sensor (165). Both ship DISABLED
# (HK_AIM_BYPASS_ENABLED undefined): a compiled no-op that passes, exactly like
# byovd_load.cpp. Their assertions activate when the aim scoring/report path + the SDK
# WM_INPUT/LL-hook stream integration land. These are USERMODE-only fixtures (no WDK /
# kernel headers); their enabled bodies include the SDK-internal aim feature header
# (sdk/src/input/AimSampler.h), so sdk/src is on the include path. The repo never
# commits a real injection tool.
set(HK_AIM_BYPASS_TESTS
    aim_injection_provenance    # signals 163/164/171
    aim_framelock_cadence)      # signal 165
foreach(_t IN LISTS HK_AIM_BYPASS_TESTS)
    add_executable(hk_bypass_${_t} ${_t}.cpp)
    target_include_directories(hk_bypass_${_t} PRIVATE
        ${CMAKE_SOURCE_DIR}/sdk/include
        ${CMAKE_SOURCE_DIR}/sdk/src)
    add_test(NAME hk_bypass_${_t} COMMAND hk_bypass_${_t})
endforeach()

# timing-side-channels merge gate (guardrail #12, signals 154/155/157/159/161). One
# bypass test per merge-gated timing sensor group. See timing/CMakeLists.txt.
add_subdirectory(timing)

# network-anomaly merge gate (guardrail #12, signals 181-189 minus the
# server-only 186). See network/CMakeLists.txt.
add_subdirectory(network)
