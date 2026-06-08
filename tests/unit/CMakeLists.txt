# tests/unit/CMakeLists.txt
# Unit test executable linking all Horkos libraries.

include(GoogleTest)

add_executable(hk_unit_tests
    test_sentinel.cpp
    test_attestation_create.cpp
    test_event_schema_sizes.cpp
    test_ioctl_sizes.cpp
)

target_include_directories(hk_unit_tests PRIVATE
    ${CMAKE_SOURCE_DIR}/attestation
    ${CMAKE_SOURCE_DIR}/sdk/include
)

target_link_libraries(hk_unit_tests PRIVATE
    hk_platform
    hk_attestation
    hk_drm
    hk_ac
    GTest::gtest
    GTest::gtest_main
)

gtest_discover_tests(hk_unit_tests)
