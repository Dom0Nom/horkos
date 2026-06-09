# bypass-tests/macos/network/CMakeLists.txt
# network-anomaly macOS bypass-test merge gate (guardrail #12). One bypass test per
# merge-gated network sensor with a macOS half (signals 182/184/187/189; 181/183/185
# are Windows-only or have no macOS half today, 188 macOS PF_ROUTE is HK-UNCERTAIN, and
# 186 is server-only). Each ships DISABLED-but-compiled (HK_NET_BYPASS_ENABLED
# undefined): a no-op that passes until the on-box read path + per-sensor fixture land
# under /tdd. Any future change under sdk/src/backends/posix/Net* (or the cross-platform
# cores) without touching the matching bypass test here is rejected (guardrail #12).
set(HK_NET_BYPASS_MACOS
    hk_bypass_net_clockdrift   # 182
    hk_bypass_net_backlog      # 184
    hk_bypass_net_probertt     # 187
    hk_bypass_net_flowowner)   # 189
foreach(_t IN LISTS HK_NET_BYPASS_MACOS)
    add_executable(${_t} ${_t}.cpp)
    target_include_directories(${_t} PRIVATE ${CMAKE_SOURCE_DIR}/sdk/include)
    add_test(NAME ${_t} COMMAND ${_t})
endforeach()
