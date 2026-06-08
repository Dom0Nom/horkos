# bypass-tests/win/CMakeLists.txt
# Windows bypass-test merge gate (guardrail #12). Phase 3 builds the test in its
# disabled form; Phase 5 defines HK_BYOVD_TEST_ENABLED and adds the fixture.

add_executable(hk_bypass_byovd byovd_load.cpp)
target_include_directories(hk_bypass_byovd PRIVATE ${CMAKE_SOURCE_DIR}/sdk/include)
add_test(NAME hk_bypass_byovd COMMAND hk_bypass_byovd)
