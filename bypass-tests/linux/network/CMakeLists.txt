# bypass-tests/linux/network/CMakeLists.txt
# network-anomaly Linux bypass-test merge gate (guardrail #12). One bypass test per
# merge-gated network sensor with a Linux half (signals 182/183/184/187/188/189; 181
# and 185 are Windows-only; 186 is server-only). Each ships DISABLED-but-compiled
# (HK_NET_BYPASS_ENABLED undefined): a no-op that passes until the on-box read path +
# per-sensor fixture land under /tdd. Any future change under sdk/src/backends/posix/
# Net* (or the cross-platform cores) without touching the matching bypass test here is
# rejected (guardrail #12).
set(HK_NET_BYPASS_LINUX
    hk_bypass_net_clockdrift   # 182
    hk_bypass_net_tcpinfo      # 183
    hk_bypass_net_backlog      # 184
    hk_bypass_net_probertt     # 187
    hk_bypass_net_route        # 188
    hk_bypass_net_flowowner)   # 189
foreach(_t IN LISTS HK_NET_BYPASS_LINUX)
    add_executable(${_t} ${_t}.cpp)
    target_include_directories(${_t} PRIVATE ${CMAKE_SOURCE_DIR}/sdk/include)
    add_test(NAME ${_t} COMMAND ${_t})
endforeach()
