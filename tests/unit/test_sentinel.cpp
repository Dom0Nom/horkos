/*
 * tests/unit/test_sentinel.cpp
 * Role: Build-system smoke test. Verifies the CMake + GTest wiring compiles
 *       and links correctly. This is not a real test of product behaviour.
 * Target platforms: all.
 */

#include <gtest/gtest.h>

TEST(Sentinel, BuildSystemSmoke) {
    EXPECT_EQ(1 + 1, 2);
}
