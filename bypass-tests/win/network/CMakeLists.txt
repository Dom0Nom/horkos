# bypass-tests/win/network/CMakeLists.txt
# network-anomaly Windows bypass-test merge gate (guardrail #12). One bypass test per
# merge-gated network sensor (signals 181/182/183/184/185/187/188/189; 186 is
# server-only, gated under bypass-tests/server/). Each ships DISABLED-but-compiled
# (HK_NET_BYPASS_ENABLED undefined): a no-op that passes, exactly like byovd_load.cpp.
# Its assertions activate when the on-box OS-read paths + per-sensor fixtures land
# under /tdd. Any future change under sdk/src/backends/win/Net* (or the cross-platform
# cores) without touching the matching bypass test here is rejected (guardrail #12).
set(HK_NET_BYPASS_WIN
    hk_bypass_net_txcadence    # 181
    hk_bypass_net_clockdrift   # 182
    hk_bypass_net_tcpinfo      # 183
    hk_bypass_net_backlog      # 184
    hk_bypass_net_inputframe   # 185
    hk_bypass_net_probertt     # 187
    hk_bypass_net_route        # 188
    hk_bypass_net_flowowner)   # 189
foreach(_t IN LISTS HK_NET_BYPASS_WIN)
    add_executable(${_t} ${_t}.cpp)
    target_include_directories(${_t} PRIVATE ${CMAKE_SOURCE_DIR}/sdk/include)
    add_test(NAME ${_t} COMMAND ${_t})
endforeach()
