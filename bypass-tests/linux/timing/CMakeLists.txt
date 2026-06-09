# bypass-tests/linux/timing/CMakeLists.txt
# timing-side-channels merge gate (guardrail #12, signal 158). One bypass test for the
# eBPF HW-breakpoint census. Ships DISABLED (HK_TIMING_TEST_ENABLED undefined): a
# compiled no-op that passes; assertions activate with the Phase-5 loader harness + the
# eBPF census attach. The repo never commits a real perf-breakpoint tool; the activated
# body uses only perf_event_open on its own synthetic guarded symbol.

add_executable(hk_bypass_timing_hw_bp_perf hw_bp_perf.cpp)  # signal 158
target_include_directories(hk_bypass_timing_hw_bp_perf PRIVATE
    ${CMAKE_SOURCE_DIR}/ac/include
    ${CMAKE_SOURCE_DIR}/sdk/include)
add_test(NAME hk_bypass_timing_hw_bp_perf COMMAND hk_bypass_timing_hw_bp_perf)
