# bypass-tests/linux/CMakeLists.txt
# Linux bypass-test merge gate (guardrail #12). Built disabled; the eBPF
# enforcement + per-test HK_*_TEST_ENABLED defines land with the loader test
# harness in a later phase. Each memory-access sensor (signals 73-81) ships a
# corresponding bypass test here so a change under kernel/linux/bpf/ has its
# matching gate.

add_executable(hk_bypass_ptrace ptrace_attach.cpp)
target_include_directories(hk_bypass_ptrace PRIVATE ${CMAKE_SOURCE_DIR}/ac/include)
add_test(NAME hk_bypass_ptrace COMMAND hk_bypass_ptrace)

# ---- Memory-access bypass tests (signals 74-78) -----------------------------
# Signals 73 (ptrace_access_check) and 81 (ptrace_traceme) extend the existing
# hk_bypass_ptrace fixture above (the impl-plan §test-strategy specifies the
# ptrace test is EXTENDED, not duplicated). 76 W^X has its own fixture below.
add_executable(hk_bypass_vm_write  vm_write_attach.cpp)
add_executable(hk_bypass_proc_mem  proc_mem_open.cpp)
add_executable(hk_bypass_wx_flip   wx_flip.cpp)
add_executable(hk_bypass_memfd_exec memfd_exec.cpp)
add_executable(hk_bypass_devmem    devmem_open.cpp)

foreach(_t hk_bypass_vm_write hk_bypass_proc_mem hk_bypass_wx_flip
           hk_bypass_memfd_exec hk_bypass_devmem)
    target_include_directories(${_t} PRIVATE ${CMAKE_SOURCE_DIR}/ac/include)
    add_test(NAME ${_t} COMMAND ${_t})
endforeach()

# process-genealogy signal 206 (LD_PRELOAD / linker hijack). DISABLED
# (HK_GENEALOGY_TEST_ENABLED undefined): a compiled no-op that passes; assertions
# activate once the eBPF loader-trust path is verified on a real kernel. Signal
# 205 reuses the existing hk_bypass_ptrace fixture (extended, not duplicated).
add_executable(hk_bypass_ld_preload_launch ld_preload_launch.cpp)
add_test(NAME hk_bypass_ld_preload_launch COMMAND hk_bypass_ld_preload_launch)

# ---- linux-ebpf-injection bypass tests (signals 82-90) ----------------------
# One per mechanism class (impl-plan §6.2). Built disabled-by-default like the
# gate above; each defines its own HK_*_TEST_ENABLED activation macro once the
# loader attach + correlator path lands on-box. The suppression half of each is
# the load-bearing assertion (it proves the catalog's FP gates actually work).
add_executable(hk_bypass_ldpreload_inject    ldpreload_inject.cpp)      # 82 + 85
add_executable(hk_bypass_got_hook            got_hook.cpp)              # 83
add_executable(hk_bypass_interp_shim         interp_shim.cpp)           # 84
add_executable(hk_bypass_memfd_dlopen        memfd_dlopen.cpp)          # 86
add_executable(hk_bypass_loadorder_interpose loadorder_interpose.cpp)   # 87
add_executable(hk_bypass_rdebug_hook         rdebug_hook.cpp)           # 88
add_executable(hk_bypass_text_inline_hook    text_inline_hook.cpp)      # 90
add_executable(hk_bypass_ld_audit_inject     ld_audit_inject.cpp)       # 89

foreach(_t hk_bypass_ldpreload_inject hk_bypass_got_hook hk_bypass_interp_shim
           hk_bypass_memfd_dlopen hk_bypass_loadorder_interpose
           hk_bypass_rdebug_hook hk_bypass_text_inline_hook
           hk_bypass_ld_audit_inject)
    target_include_directories(${_t} PRIVATE ${CMAKE_SOURCE_DIR}/ac/include)
    add_test(NAME ${_t} COMMAND ${_t})
endforeach()

# ---- linux-module-integrity bypass tests (signals 91-99) --------------------
# One per evasion class the domain is designed to catch (impl-plan §8.2). Built
# disabled-by-default like the gates above; each defines its own
# HK_*_TEST_ENABLED activation macro once the host-integrity aggregator + eBPF
# loader path lands on a live-kernel CI runner. The suppression / coverage-gap
# halves are the load-bearing assertions (they prove the FP gates work and that
# "can't read" is never treated as "detected").
add_executable(hk_bypass_module_unlink       module_unlink_hidden.cpp)     # 92
add_executable(hk_bypass_ftrace_commit_creds  ftrace_hook_commit_creds.cpp) # 93
add_executable(hk_bypass_devmem_write         devmem_write_open.cpp)        # 98
add_executable(hk_bypass_msr_lstar            msr_lstar_write.cpp)          # 99
add_executable(hk_bypass_sensor_unavailable   sensor_unavailable.cpp)       # general

foreach(_t hk_bypass_module_unlink hk_bypass_ftrace_commit_creds
           hk_bypass_devmem_write hk_bypass_msr_lstar
           hk_bypass_sensor_unavailable)
    target_include_directories(${_t} PRIVATE ${CMAKE_SOURCE_DIR}/ac/include)
    add_test(NAME ${_t} COMMAND ${_t})
endforeach()

# ---- linux-proton-wine bypass tests (signals 100-108) -----------------------
# Separate subdirectory (one test per catalog evasion). Disabled-by-default like
# the gates above; activation macros + replay mode land with the Deck-class CI
# loader harness. See proton_wine/CMakeLists.txt.
add_subdirectory(proton_wine)

# ---- hardware-input-devices evdev/uinput provenance bypass test (signal 140) -
# One bypass test for the device-trust evdev/uinput provenance sensor. Ships DISABLED
# (HK_DEVICE_TRUST_BYPASS_ENABLED undefined): a compiled no-op that passes, like the
# memory-access gates. Its assertions activate when the bpf ringbuf drain + the server
# creator-PID allowlist path land. It includes the pure classifier under
# sdk/src/backends/posix/input, so that backend dir is on the include path. The repo
# never commits a real injection tool; the activated body uses only /dev/uinput on its
# own synthetic device.
add_executable(hk_bypass_uinput_virtual_provenance uinput_virtual_provenance.cpp)  # 140
target_include_directories(hk_bypass_uinput_virtual_provenance PRIVATE
    ${CMAKE_SOURCE_DIR}/sdk/include
    ${CMAKE_SOURCE_DIR}/sdk/src/backends/posix)
add_test(NAME hk_bypass_uinput_virtual_provenance
    COMMAND hk_bypass_uinput_virtual_provenance)

# ---- memory-integrity-selfcheck bypass test (signals 145/146/152, Linux) ----
# One bypass test for the Linux self-integrity kernel-corroborated sensors. Ships
# DISABLED (HK_SELFCHECK_TEST_ENABLED undefined): a compiled no-op that passes, like
# the gates above. Its assertions activate when the eBPF/LKM self-read path + the
# loader harness land. The repo never commits a real self-patching tool.
add_executable(hk_bypass_self_text_patch self_text_patch.cpp)  # 145/146/152
target_include_directories(hk_bypass_self_text_patch PRIVATE
    ${CMAKE_SOURCE_DIR}/ac/include
    ${CMAKE_SOURCE_DIR}/sdk/include)
add_test(NAME hk_bypass_self_text_patch COMMAND hk_bypass_self_text_patch)

# ---- timing-side-channels HW-breakpoint census bypass test (signal 158) -----
# One bypass test for the eBPF HW-breakpoint census. See timing/CMakeLists.txt.
add_subdirectory(timing)

# network-anomaly merge gate (guardrail #12, signals 181-189 minus the
# server-only 186). See network/CMakeLists.txt.
add_subdirectory(network)
