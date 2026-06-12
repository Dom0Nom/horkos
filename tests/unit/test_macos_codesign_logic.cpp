/*
 * Role: Host-buildable pure-logic tests for the macOS code-signing probe FP-gate
 *       cores (macos-codesign-integrity, signals 118-126). The probe TUs split a
 *       PURE decision core (host-runnable integer logic) from the impure
 *       csops / Sec-API / ES read; compiled with HK_CS_PROBE_PURE_ONLY the cores
 *       link with no macOS headers. This pins the catalog FP gates: csflags baseline
 *       diff (only CS_KILL/CS_HARD clearing flags), cdhash fold/compare,
 *       team-id classification, entitlement security-key diff (OS-injected
 *       allowlist ignored), N-of-M dynamic-validity confirmation, and the
 *       CS_INVALIDATED<->exec-mmap correlation window.
 * Target platforms: all (the cores are plain C/C++ above the platform guard).
 * Interface: includes CsIntegrityProbe.h / CsScan.h; the *.cpp cores are added to
 *            the test target (compiled HK_CS_PROBE_PURE_ONLY).
 */

#include <cstdint>
#include <cstddef>

#include <gtest/gtest.h>

#include "CsIntegrityProbe.h"   // cs_flags_drifted, cs_cdhash_*, cs_teamid_classify, cs_entitlement_added
#include "CsScan.h"             // HkEsObservation, HK_ES_OBS_*

// Pure cores declared in their probe TUs but not in a shared header (they are
// internal seams); declare them here for the test link.
extern "C" bool hk_nofm_confirm(const uint8_t *outcomes, size_t count,
                                uint32_t threshold_n);
extern "C" bool hk_cs_invalidation_correlates(const HkEsObservation *invalidated,
                                              const HkEsObservation *mmap_obs,
                                              uint64_t window_ns);

// csflags bit values (mirror of <sys/codesign.h> / the probe's local copy).
namespace {
constexpr uint32_t CS_HARD    = 0x00000100u;
constexpr uint32_t CS_KILL    = 0x00000200u;
constexpr uint32_t CS_RUNTIME = 0x00010000u;
constexpr uint32_t PROT_EXEC  = 0x4u;
}  // namespace

// ---- Signal 118: csflags baseline diff ------------------------------------

TEST(CsFlagsDrift, CriticalBitClearedFromBaselineFlags)
{
    // Baseline had CS_KILL|CS_HARD; observed cleared both -> both reported.
    uint32_t baseline = CS_KILL | CS_HARD | CS_RUNTIME;
    uint32_t observed = CS_RUNTIME;  // kill + hard stripped
    uint32_t missing = cs_flags_drifted(baseline, observed);
    EXPECT_EQ(missing, CS_KILL | CS_HARD);
}

TEST(CsFlagsDrift, RuntimeClearedNotFlagged)
{
    // CS_RUNTIME cleared on a baseline that had it is NOT a critical drift
    // (Rosetta/debug carry differing-but-legit runtime bits).
    uint32_t baseline = CS_KILL | CS_HARD | CS_RUNTIME;
    uint32_t observed = CS_KILL | CS_HARD;  // only runtime gone
    EXPECT_EQ(cs_flags_drifted(baseline, observed), 0u);
}

TEST(CsFlagsDrift, BitAbsentFromBaselineNeverFlagged)
{
    // A baseline that never had CS_KILL cannot drift on it (debug-signed build).
    uint32_t baseline = CS_HARD;
    uint32_t observed = 0;  // hard cleared -> only CS_HARD reported, not CS_KILL
    EXPECT_EQ(cs_flags_drifted(baseline, observed), CS_HARD);
}

TEST(CsFlagsDrift, CleanMatchNoDrift)
{
    uint32_t mask = CS_KILL | CS_HARD;
    EXPECT_EQ(cs_flags_drifted(mask, mask), 0u);
}

// ---- Signal 119: cdhash fold / compare ------------------------------------

TEST(CdHash, FoldIsDeterministicAndDiffersOnChange)
{
    uint8_t a[32]; for (int i = 0; i < 32; ++i) a[i] = (uint8_t)i;
    uint8_t b[32]; for (int i = 0; i < 32; ++i) b[i] = (uint8_t)i;
    b[5] ^= 0x40;  // patch one byte
    EXPECT_EQ(cs_cdhash_fold(a, 32), cs_cdhash_fold(a, 32));
    EXPECT_NE(cs_cdhash_fold(a, 32), cs_cdhash_fold(b, 32));
}

TEST(CdHash, EqualLengthAwareNoOverRead)
{
    uint8_t a[20]; for (int i = 0; i < 20; ++i) a[i] = (uint8_t)i;
    uint8_t b[32]; for (int i = 0; i < 32; ++i) b[i] = (uint8_t)i;
    EXPECT_TRUE(cs_cdhash_equal(a, 20, a, 20));
    EXPECT_FALSE(cs_cdhash_equal(a, 20, b, 32));  // length mismatch = mismatch
    EXPECT_FALSE(cs_cdhash_equal(nullptr, 20, a, 20));
}

// ---- Signal 122: team-id classification -----------------------------------

TEST(TeamId, PlatformBinaryShortCircuits)
{
    uint8_t host[16] = "TEAMHOST";
    uint8_t dy[16]   = "OTHER";
    EXPECT_EQ(cs_teamid_classify(dy, 16, host, 16, /*is_platform*/true, false),
              HK_CS_TEAMID_APPLE_PLATFORM);
}

TEST(TeamId, AllowlistedBeatsForeign)
{
    uint8_t host[16] = "TEAMHOST";
    uint8_t dy[16]   = "STEAMXYZ";
    EXPECT_EQ(cs_teamid_classify(dy, 16, host, 16, false, /*allowlisted*/true),
              HK_CS_TEAMID_ALLOWLISTED);
}

TEST(TeamId, SameTeamRecognized)
{
    uint8_t host[16] = "TEAMHOST";
    uint8_t dy[16]   = "TEAMHOST";
    EXPECT_EQ(cs_teamid_classify(dy, 16, host, 16, false, false),
              HK_CS_TEAMID_SAME_TEAM);
}

TEST(TeamId, ForeignTeamFlagged)
{
    uint8_t host[16] = "TEAMHOST";
    uint8_t dy[16]   = "FOREIGN1";
    EXPECT_EQ(cs_teamid_classify(dy, 16, host, 16, false, false),
              HK_CS_TEAMID_FOREIGN);
}

TEST(TeamId, EmptyDylibTeamIsForeignNotSameTeam)
{
    // An unsigned/ad-hoc dylib (no team id) must NOT be treated as same-team.
    uint8_t host[16] = "TEAMHOST";
    uint8_t dy[16]   = {0};
    EXPECT_EQ(cs_teamid_classify(dy, 16, host, 16, false, false),
              HK_CS_TEAMID_FOREIGN);
}

// ---- Signal 126: entitlement security-key diff ----------------------------

TEST(Entitlement, AddedGetTaskAllowFlagged)
{
    uint32_t disk   = 0;
    uint32_t kernel = HK_ENT_GET_TASK_ALLOW;
    EXPECT_EQ(cs_entitlement_added(disk, kernel, /*os_injected*/0),
              HK_ENT_GET_TASK_ALLOW);
}

TEST(Entitlement, OsInjectedAllowlistIgnored)
{
    // A Rosetta/Apple-shim OS-injected entitlement on the allowlist is not drift.
    uint32_t disk   = 0;
    uint32_t kernel = HK_ENT_DEBUGGER;
    EXPECT_EQ(cs_entitlement_added(disk, kernel, /*os_injected*/HK_ENT_DEBUGGER),
              0u);
}

TEST(Entitlement, DiskEntitlementNotDrift)
{
    // An entitlement present on disk AND in the kernel blob is legitimate.
    uint32_t disk   = HK_ENT_DISABLE_LV;
    uint32_t kernel = HK_ENT_DISABLE_LV;
    EXPECT_EQ(cs_entitlement_added(disk, kernel, 0), 0u);
}

TEST(Entitlement, MixedAddedAndAllowlisted)
{
    uint32_t disk   = 0;
    uint32_t kernel = HK_ENT_GET_TASK_ALLOW | HK_ENT_DEBUGGER;
    // debugger is OS-injected-allowlisted; only get-task-allow is real drift.
    EXPECT_EQ(cs_entitlement_added(disk, kernel, HK_ENT_DEBUGGER),
              HK_ENT_GET_TASK_ALLOW);
}

// ---- Signal 120: N-of-M dynamic-validity confirmation ---------------------

TEST(NofM, BelowThresholdNoEmit)
{
    uint8_t outcomes[5] = {1, 0, 1, 0, 0};  // 2 fails, threshold 3
    EXPECT_FALSE(hk_nofm_confirm(outcomes, 5, 3));
}

TEST(NofM, AtThresholdConfirms)
{
    uint8_t outcomes[5] = {1, 1, 0, 1, 0};  // 3 fails
    EXPECT_TRUE(hk_nofm_confirm(outcomes, 5, 3));
}

TEST(NofM, SingleTransientNeverConfirms)
{
    uint8_t outcomes[5] = {0, 0, 1, 0, 0};  // one transient JIT failure
    EXPECT_FALSE(hk_nofm_confirm(outcomes, 5, 3));
}

// ---- Signal 121: CS_INVALIDATED <-> exec-mmap correlation -----------------

namespace {
HkEsObservation make_inval(uint32_t pid, uint64_t ts) {
    HkEsObservation o{};
    o.kind = HK_ES_OBS_CS_INVALIDATED;
    o.target_pid = pid;
    o.timestamp_ns = ts;
    return o;
}
HkEsObservation make_mmap(uint32_t pid, uint64_t ts, uint32_t prot, uint32_t platform) {
    HkEsObservation o{};
    o.kind = HK_ES_OBS_MMAP;
    o.target_pid = pid;
    o.timestamp_ns = ts;
    o.protection = prot;
    o.is_platform_src = platform;
    return o;
}
constexpr uint64_t kWindow = 2ull * 1000ull * 1000ull * 1000ull;  // 2 s
}  // namespace

TEST(InvalidationCorrelator, InWindowNonPlatformExecMmapCorrelates)
{
    auto mm = make_mmap(42, 1000, PROT_EXEC, /*platform*/0);
    auto iv = make_inval(42, 1000 + kWindow / 2);
    EXPECT_TRUE(hk_cs_invalidation_correlates(&iv, &mm, kWindow));
}

TEST(InvalidationCorrelator, PlatformFdSuppressed)
{
    // Shared-cache repaging / platform-FD COW is legitimate.
    auto mm = make_mmap(42, 1000, PROT_EXEC, /*platform*/1);
    auto iv = make_inval(42, 1000 + 1);
    EXPECT_FALSE(hk_cs_invalidation_correlates(&iv, &mm, kWindow));
}

TEST(InvalidationCorrelator, NonExecMmapSuppressed)
{
    auto mm = make_mmap(42, 1000, /*read-only*/0x1, 0);
    auto iv = make_inval(42, 1000 + 1);
    EXPECT_FALSE(hk_cs_invalidation_correlates(&iv, &mm, kWindow));
}

TEST(InvalidationCorrelator, OutOfWindowSuppressed)
{
    auto mm = make_mmap(42, 1000, PROT_EXEC, 0);
    auto iv = make_inval(42, 1000 + kWindow + 1);  // just past the window
    EXPECT_FALSE(hk_cs_invalidation_correlates(&iv, &mm, kWindow));
}

TEST(InvalidationCorrelator, DifferentPidSuppressed)
{
    auto mm = make_mmap(42, 1000, PROT_EXEC, 0);
    auto iv = make_inval(99, 1000 + 1);  // different target
    EXPECT_FALSE(hk_cs_invalidation_correlates(&iv, &mm, kWindow));
}

TEST(InvalidationCorrelator, MmapAfterInvalidationSuppressed)
{
    // The mmap must PRECEDE the invalidation (cause before effect).
    auto mm = make_mmap(42, 2000, PROT_EXEC, 0);
    auto iv = make_inval(42, 1000);  // invalidation earlier than the mmap
    EXPECT_FALSE(hk_cs_invalidation_correlates(&iv, &mm, kWindow));
}
