/*
 * tests/unit/test_thread_start_mismatch.cpp
 * Role: Host-buildable unit tests for the thread start-address mismatch
 *       classifier (sdk/src/backends/win/ThreadProvenanceWin.h, signal 23).
 *       Proves the decision table: kernel-unbacked + user-in-module spoof fires;
 *       the reverse (normal JIT/thunk) does not; agreement-modulo-ntdll-shim does
 *       not; and the absent-kernel-start case (the Ex-notify limitation) yields no
 *       false positive. No live thread needed — the classifier is pure.
 * Target platforms: host (any).
 * Interface: exercises hk::sdk::threadprov::classify_start_mismatch against
 *       fixture inputs.
 */

#include <gtest/gtest.h>

#include "backends/win/ThreadProvenanceWin.h"

using hk::sdk::threadprov::classify_start_mismatch;
using hk::sdk::threadprov::Region;
using hk::sdk::threadprov::StartMismatchInput;

namespace {

StartMismatchInput Base()
{
    StartMismatchInput in{};
    in.kernel_start_address = 0x7FFF'0000'1000;
    in.user_start_address = 0x0000'0001'4000'1000; /* a benign in-module addr */
    in.kernel_start_region = Region::Private;       /* unbacked */
    in.user_start_region = Region::Image;           /* looks in-module */
    in.user_in_known_module = true;
    in.is_ntdll_thread_shim = false;
    return in;
}

} // namespace

TEST(ThreadStartMismatch, SpoofSignatureFires)
{
    // Kernel start unbacked, user start dressed up as in-module, addrs differ.
    EXPECT_TRUE(classify_start_mismatch(Base()));
}

TEST(ThreadStartMismatch, ReverseDirectionDoesNotFire)
{
    // Normal JIT/thunk: user start unbacked, kernel start in a real image.
    StartMismatchInput in = Base();
    in.kernel_start_region = Region::Image;
    in.user_start_region = Region::Private;
    in.user_in_known_module = false;
    EXPECT_FALSE(classify_start_mismatch(in));
}

TEST(ThreadStartMismatch, NtdllShimNeverFlags)
{
    StartMismatchInput in = Base();
    in.is_ntdll_thread_shim = true;
    EXPECT_FALSE(classify_start_mismatch(in));
}

TEST(ThreadStartMismatch, EqualAddressesNoMismatch)
{
    StartMismatchInput in = Base();
    in.user_start_address = in.kernel_start_address;
    EXPECT_FALSE(classify_start_mismatch(in));
}

TEST(ThreadStartMismatch, AbsentKernelStartIsConservative)
{
    // The Ex-notify limitation: no kernel start captured. Must NOT guess a spoof.
    StartMismatchInput in = Base();
    in.kernel_start_address = 0;
    EXPECT_FALSE(classify_start_mismatch(in));
}

TEST(ThreadStartMismatch, UserNotInKnownModuleDoesNotFire)
{
    StartMismatchInput in = Base();
    in.user_in_known_module = false;
    EXPECT_FALSE(classify_start_mismatch(in));
}
