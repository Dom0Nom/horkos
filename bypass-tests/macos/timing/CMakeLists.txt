# bypass-tests/macos/timing/CMakeLists.txt
# timing-side-channels merge gate (guardrail #12, signal 160). One bypass test for the
# ES Mach exception-port audit. Ships DISABLED (HK_TIMING_TEST_ENABLED undefined): a
# compiled no-op that passes; assertions activate with the Phase-5 ES fixture + the
# foreign-task exception-port resolution. The test asserts BOTH the foreign-owner
# classification AND the guardrail-#7 ES-reply invariant. The repo never commits a real
# debugger fixture.

add_executable(hk_bypass_timing_lldb_exc_port lldb_exc_port.cpp)  # signal 160
target_include_directories(hk_bypass_timing_lldb_exc_port PRIVATE
    ${CMAKE_SOURCE_DIR}/ac/include
    ${CMAKE_SOURCE_DIR}/sdk/include)
add_test(NAME hk_bypass_timing_lldb_exc_port COMMAND hk_bypass_timing_lldb_exc_port)
