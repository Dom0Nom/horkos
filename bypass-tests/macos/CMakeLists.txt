# bypass-tests/macos/CMakeLists.txt
# macOS bypass-test merge gate (guardrail #12). Built disabled in Phase 5; each
# fixture activates once the daemon injection detection + the per-signal
# HK_*_TEST_ENABLED define land in a later phase. Disabled fixtures return 0 so
# the gate stays green until enforcement/correlation lands.

# Each fixture maps to one macos-injection signal (109-117). Adding a sensor
# under kernel/macos/es/ or daemon/macos/ requires its bypass test here.
set(hk_macos_bypass
    dylib_inject            # signal 112 (existing)
    task_for_pid_control    # signals 109/110
    mmap_exec_foreign       # signal 111
    proc_info_recon         # signal 115
    exc_port_hijack         # signal 113
    remote_thread           # signal 114
    ptrace_attach           # signal 116
    text_patch              # signal 117
    # macos-codesign-integrity (signals 118-126). Disabled-but-compiled until the
    # Phase-5 signed fixture + daemon enforcement land (HK_CS_TEST_ENABLED gate).
    csflags_strip           # signal 118
    cdhash_swap             # signal 119
    dynamic_validity_patch  # signal 120
    cs_invalidate_mmap      # signal 121
    dylib_teamid_inject     # signal 122
    amfid_taskport          # signal 123
    amfi_posture_bootarg    # signal 124
    gatekeeper_xattr_strip  # signal 125
    entitlement_inject      # signal 126
    # memory-integrity-selfcheck (signals 145/146/152, macOS). Disabled-but-compiled
    # until the Phase-5 fixture + the daemon self-task mach_vm_* self-read path land
    # (HK_SELFCHECK_TEST_ENABLED gate). One bypass test for the daemon self-read sensors.
    self_text_patch         # signals 145/146/152
)

foreach(_t IN LISTS hk_macos_bypass)
    add_executable(hk_bypass_${_t} ${_t}.cpp)
    target_include_directories(hk_bypass_${_t} PRIVATE
        ${CMAKE_SOURCE_DIR}/ac/include      # horkos/ac.h (flag surface)
        ${CMAKE_SOURCE_DIR}/sdk/include)    # horkos/event_schema_macos.h
    add_test(NAME hk_bypass_${_t} COMMAND hk_bypass_${_t})
endforeach()

# timing-side-channels merge gate (guardrail #12, signal 160). One bypass test for the
# ES Mach exception-port audit. See timing/CMakeLists.txt.
add_subdirectory(timing)

# network-anomaly merge gate (guardrail #12, signals 181-189 minus the
# server-only 186). See network/CMakeLists.txt.
add_subdirectory(network)
