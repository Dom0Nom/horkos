# bypass-tests/linux/CMakeLists.txt
# Linux bypass-test merge gate (guardrail #12). Built disabled in Phase 5; the
# eBPF enforcement + HK_PTRACE_TEST_ENABLED land in a later phase.

add_executable(hk_bypass_ptrace ptrace_attach.cpp)
target_include_directories(hk_bypass_ptrace PRIVATE ${CMAKE_SOURCE_DIR}/ac/include)
add_test(NAME hk_bypass_ptrace COMMAND hk_bypass_ptrace)
