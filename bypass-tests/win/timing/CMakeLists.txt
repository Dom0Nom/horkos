# bypass-tests/win/timing/CMakeLists.txt
# timing-side-channels merge gate (guardrail #12, signals 154/155/157/159/161). One
# bypass test per merge-gated timing sensor group. Each ships DISABLED
# (HK_TIMING_TEST_ENABLED undefined): a compiled no-op that passes, exactly like
# byovd_load.cpp; assertions activate with the Phase-5 timing fixture harness. The
# enabled bodies drive the AC timing surface, so ac/include is on the include path; the
# 155 VM test additionally needs the kernel-private freq-skew mirror, so kernel/win/include
# is on the path too. The repo never commits a real stepping/hooking/VM tool.

set(HK_TIMING_BYPASS_TESTS
    hw_bp_stepper       # signals 154 + 161
    foreign_veh         # signal 154
    time_hook           # signal 157
    exc_hook            # signal 159
    tsc_offset_vm)      # signal 155
foreach(_t IN LISTS HK_TIMING_BYPASS_TESTS)
    add_executable(hk_bypass_timing_${_t} ${_t}.cpp)
    target_include_directories(hk_bypass_timing_${_t} PRIVATE
        ${CMAKE_SOURCE_DIR}/ac/include
        ${CMAKE_SOURCE_DIR}/sdk/include
        ${CMAKE_SOURCE_DIR}/kernel/win/include)
    add_test(NAME hk_bypass_timing_${_t} COMMAND hk_bypass_timing_${_t})
endforeach()
