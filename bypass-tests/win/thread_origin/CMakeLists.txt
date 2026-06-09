# bypass-tests/win/thread_origin/CMakeLists.txt
# win-kernel-thread-injection merge-gate suite (guardrail #12).
#
# Two targets:
#   hk_bypass_thread_origin   — the live-fixture gate. Windows-only; ships DISABLED
#                               (HK_THREAD_ORIGIN_TEST_ENABLED undefined) and passes
#                               as a no-op until the kernel thread-create plane, the
#                               grown event schema, and the ETW-TI replay fixtures
#                               land. Mirrors byovd_load / callback_unhook.
#   hk_bypass_correlator_replay — HOST-RUNNABLE now. Replays a recorded-shaped
#                               ETW-TI sequence through the platform-free
#                               InjectCorrelator and asserts the injection chain is
#                               not silently accepted. Built on every platform so
#                               the gate has a real, executing assertion today.

# Live-fixture gate (Windows only — pulls <windows.h> in its enabled body).
if(WIN32)
    add_executable(hk_bypass_thread_origin thread_origin.cpp)
    target_include_directories(hk_bypass_thread_origin PRIVATE
        ${CMAKE_SOURCE_DIR}/sdk/include
        ${CMAKE_SOURCE_DIR}/kernel/win/include)
    add_test(NAME hk_bypass_thread_origin COMMAND hk_bypass_thread_origin)
endif()

# Host-runnable correlator replay (platform-free; built and run everywhere).
# Compiles the EtwTiConsumer TU directly (its InjectCorrelator::feed body is the
# platform-free part; the live PPL session path is excluded because the test does
# not define HK_PLATFORM_WINDOWS / _WIN32, so no Win32 headers are pulled).
add_executable(hk_bypass_correlator_replay
    correlator_replay.cpp
    ${CMAKE_SOURCE_DIR}/sdk/src/backends/win/EtwTiConsumer.cpp)
target_include_directories(hk_bypass_correlator_replay PRIVATE
    ${CMAKE_SOURCE_DIR}/sdk/src/backends/win
    ${CMAKE_SOURCE_DIR}/sdk/include)
add_test(NAME hk_bypass_correlator_replay COMMAND hk_bypass_correlator_replay)
