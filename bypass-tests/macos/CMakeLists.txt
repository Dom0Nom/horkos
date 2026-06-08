# bypass-tests/macos/CMakeLists.txt
# macOS bypass-test merge gate (guardrail #12). Built disabled in Phase 5; the
# daemon injection detection + HK_DYLIB_TEST_ENABLED land in a later phase.

add_executable(hk_bypass_dylib dylib_inject.cpp)
target_include_directories(hk_bypass_dylib PRIVATE ${CMAKE_SOURCE_DIR}/ac/include)
add_test(NAME hk_bypass_dylib COMMAND hk_bypass_dylib)
