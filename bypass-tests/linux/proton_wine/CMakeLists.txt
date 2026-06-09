# bypass-tests/linux/proton_wine/CMakeLists.txt
# Linux Proton/Wine/Steam-Deck bypass-test merge gate (guardrail #12). One test per
# catalog evasion (signals 100-108). Built disabled-by-default like the sibling
# linux gates: each defines its own HK_PW_*_TEST_ENABLED activation macro once the
# eBPF loader attach + verifier path lands on a BTF-capable Deck-class CI runner.
# The suppression / faithfully-reported halves are the load-bearing assertions (they
# prove the FP gates work and that the named evasion is never silently accepted).
# Where the live kernel hook is UNCERTAIN (103/104/105/107/108 — see impl-plan
# Risks), the test ALSO runs in replay mode (recorded ring record -> Loader.cpp +
# linux_proton.rs), so the decode/classify path is gated before the live hook is
# confirmed on-box.

add_executable(hk_bypass_pw_dlloverride bypass_dlloverride_inject.cpp) # 100
add_executable(hk_bypass_pw_foreign_map bypass_foreign_so_map.cpp)     # 101
add_executable(hk_bypass_pw_cross_mem   bypass_cross_mem_scan.cpp)     # 102
add_executable(hk_bypass_pw_setns       bypass_setns_breach.cpp)       # 103
add_executable(hk_bypass_pw_module      bypass_post_boot_lkm.cpp)      # 104
add_executable(hk_bypass_pw_rootfs      bypass_rootfs_remount.cpp)     # 105
add_executable(hk_bypass_pw_frame       bypass_frame_siphon.cpp)       # 106
add_executable(hk_bypass_pw_builtin     bypass_builtin_stomp.cpp)      # 107
add_executable(hk_bypass_pw_uinput      bypass_uinput_macro.cpp)       # 108

foreach(_t hk_bypass_pw_dlloverride hk_bypass_pw_foreign_map hk_bypass_pw_cross_mem
           hk_bypass_pw_setns hk_bypass_pw_module hk_bypass_pw_rootfs
           hk_bypass_pw_frame hk_bypass_pw_builtin hk_bypass_pw_uinput)
    target_include_directories(${_t} PRIVATE ${CMAKE_SOURCE_DIR}/ac/include)
    add_test(NAME ${_t} COMMAND ${_t})
endforeach()
