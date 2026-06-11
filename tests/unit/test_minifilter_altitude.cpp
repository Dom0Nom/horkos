/*
 * tests/unit/test_minifilter_altitude.cpp
 * Role: Host-buildable unit tests for the minifilter altitude census classifier
 *       (sdk/src/backends/win/minifilter_altitude.h, signal 6). Proves the FP
 *       discipline: altitude-occupancy alone is never a verdict; only an
 *       UNALLOCATED altitude OR a FAILED Authenticode chain on a filter
 *       adjacent-above Horkos is SUSPECT; legitimate signed/allowlisted filters
 *       above Horkos stay BENIGN. No live FltMgr needed — the classifier is pure.
 * Target platforms: host (any).
 * Interface: exercises hk::sdk::mf::ClassifyNeighbor against fixture rows.
 */

#include <gtest/gtest.h>

#include "backends/win/minifilter_altitude.h"

using hk::sdk::mf::AuthResult;
using hk::sdk::mf::ClassifyNeighbor;
using hk::sdk::mf::FilterRow;
using hk::sdk::mf::Verdict;

namespace {
constexpr double kHorkos = 385201.0;

FilterRow MakeRow(double alt, bool valid, bool allocated, AuthResult auth,
                  bool allowlisted)
{
    FilterRow r{};
    r.altitude = alt;
    r.altitude_valid = valid;
    r.altitude_allocated = allocated;
    r.auth = auth;
    r.publisher_allowlisted = allowlisted;
    return r;
}
} // namespace

TEST(MinifilterAltitude, BelowHorkosNeverSuspect)
{
    /* A filter below us cannot pre-empt our I/O; never suspect even if unsigned
     * and unallocated. */
    auto row = MakeRow(100000.0, true, false, AuthResult::Failed, false);
    EXPECT_EQ(Verdict::Benign, ClassifyNeighbor(row, kHorkos));
}

TEST(MinifilterAltitude, AllocatedSignedAboveIsBenign)
{
    /* Defender/OneDrive-class: allocated altitude above us, signed. Legitimate. */
    auto row = MakeRow(385300.0, true, true, AuthResult::Trusted, false);
    EXPECT_EQ(Verdict::Benign, ClassifyNeighbor(row, kHorkos));
}

TEST(MinifilterAltitude, UnallocatedAboveIsSuspect)
{
    /* Squatting at an unallocated altitude above us = suspect. */
    auto row = MakeRow(385250.0, true, false, AuthResult::Trusted, false);
    EXPECT_EQ(Verdict::Suspect, ClassifyNeighbor(row, kHorkos));
}

TEST(MinifilterAltitude, UnallocatedButAllowlistedIsBenign)
{
    /* An allowlisted publisher overrides the unallocated flag (vendor exception). */
    auto row = MakeRow(385250.0, true, false, AuthResult::Trusted, true);
    EXPECT_EQ(Verdict::Benign, ClassifyNeighbor(row, kHorkos));
}

TEST(MinifilterAltitude, AllocatedFailedAuthAboveIsSuspect)
{
    /* Allocated altitude but failed signature and not allowlisted = suspect. */
    auto row = MakeRow(385300.0, true, true, AuthResult::Failed, false);
    EXPECT_EQ(Verdict::Suspect, ClassifyNeighbor(row, kHorkos));
}

TEST(MinifilterAltitude, AllocatedFailedAuthButAllowlistedIsBenign)
{
    auto row = MakeRow(385300.0, true, true, AuthResult::Failed, true);
    EXPECT_EQ(Verdict::Benign, ClassifyNeighbor(row, kHorkos));
}

TEST(MinifilterAltitude, UnknownAuthAtAllocatedAltitudeIsBenign)
{
    /* Unknown auth is not, on its own, a Failed verdict. */
    auto row = MakeRow(385300.0, true, true, AuthResult::Unknown, false);
    EXPECT_EQ(Verdict::Benign, ClassifyNeighbor(row, kHorkos));
}

TEST(MinifilterAltitude, MalformedAltitudeAboveIsSuspectUnlessAllowlisted)
{
    auto bad = MakeRow(0.0, false, false, AuthResult::Unknown, false);
    EXPECT_EQ(Verdict::Suspect, ClassifyNeighbor(bad, kHorkos));

    auto badAllow = MakeRow(0.0, false, false, AuthResult::Unknown, true);
    EXPECT_EQ(Verdict::Benign, ClassifyNeighbor(badAllow, kHorkos));
}

TEST(MinifilterAltitude, OccupancyAloneIsNeverAVerdict)
{
    /* The core FP rule: an allocated, signed filter merely sitting above us is
     * benign no matter how close the altitude. */
    auto adjacent = MakeRow(385201.5, true, true, AuthResult::Trusted, false);
    EXPECT_EQ(Verdict::Benign, ClassifyNeighbor(adjacent, kHorkos));
}

TEST(MinifilterAltitude, AllocatedBandsMatchPublishedTable)
{
    using hk::sdk::mf::is_allocated_altitude;
    // In-band altitudes (Microsoft load-order groups) are allocated.
    EXPECT_TRUE(is_allocated_altitude(425000.0));  // Filter
    EXPECT_TRUE(is_allocated_altitude(325000.0));  // Anti-Virus
    EXPECT_TRUE(is_allocated_altitude(325000.3));  // fractional within Anti-Virus
    EXPECT_TRUE(is_allocated_altitude(45000.0));   // Bottom
    EXPECT_TRUE(is_allocated_altitude(170000.0));  // Imaging (lower edge)
    EXPECT_TRUE(is_allocated_altitude(175000.0));  // Imaging (upper edge)
    EXPECT_TRUE(is_allocated_altitude(15000.0));   // Infrastructure (<20000)
}

TEST(MinifilterAltitude, GapAltitudesAreUnallocated)
{
    using hk::sdk::mf::is_allocated_altitude;
    // Gaps between Microsoft bands were never allocated — squats.
    EXPECT_FALSE(is_allocated_altitude(35000.0));   // gap System..Bottom (30000-39999)
    EXPECT_FALSE(is_allocated_altitude(55000.0));   // gap Bottom..Copy Protection
    EXPECT_FALSE(is_allocated_altitude(177000.0));  // gap Imaging..(175001-179999)
    EXPECT_FALSE(is_allocated_altitude(315000.0));  // gap Replication..Anti-Virus
    EXPECT_FALSE(is_allocated_altitude(500000.0));  // above all bands
    EXPECT_FALSE(is_allocated_altitude(0.0));       // not a real altitude
    EXPECT_FALSE(is_allocated_altitude(-1.0));
}
