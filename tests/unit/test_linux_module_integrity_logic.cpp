/*
 * Role: Host-runnable pure-logic tests for the linux-module-integrity auditors
 *       (signals 91-99). The proc/sysfs/debugfs PARSERS and decision cores are
 *       plain C++17 (no libbpf, no Linux-only syscalls in the tested paths) so
 *       they run above the platform guard against captured text fixtures. Covers
 *       the load-bearing correctness rule of the domain: a coverage gap
 *       (kptr_restrict / unmounted fs) emits SENSOR_UNAVAILABLE and NEVER a false
 *       detection, plus the per-signal FP gates (livepatch relocation not flagged,
 *       DKMS rebuild not flagged, signed-owner ftrace not flagged, benign MSR not
 *       flagged).
 * Target platforms: host (build box).
 * Interface: gtest; compiles the module-trust sensor .cpp sources directly (see
 *            tests/unit/CMakeLists.txt). A capturing sink records emitted events.
 */

#include <gtest/gtest.h>

#include <cstring>
#include <vector>

#include "BpfEnumerate.h"
#include "FtraceAudit.h"
#include "HostIntegritySensors.h"
#include "KallsymsAudit.h"
#include "KprobeAudit.h"
#include "LockdownPosture.h"
#include "ModuleDiskDrift.h"
#include "ModuleViewDiff.h"
#include "MsrPathResolver.h"
#include "SymbolMap.h"

using namespace horkos::modint;

// ---- Capturing sink --------------------------------------------------------
namespace {
struct CapturedEvent {
    uint32_t type = 0;
    std::vector<uint8_t> payload;
};
std::vector<CapturedEvent> g_events;

void CaptureSink(const hk_event_header* hdr, const void* payload) {
    CapturedEvent e;
    e.type = hdr->type;
    const auto* p = static_cast<const uint8_t*>(payload);
    e.payload.assign(p, p + hdr->payload_bytes);
    g_events.push_back(std::move(e));
}

void ResetEvents() { g_events.clear(); }

int CountOfType(uint32_t type) {
    int n = 0;
    for (const auto& e : g_events) if (e.type == type) ++n;
    return n;
}

// Build a symbol map fixture with a core range and a sensitive symbol set.
HkSymbolMap MakeMap(uint64_t core_lo, uint64_t core_hi,
                    std::map<std::string, uint64_t> syms,
                    bool addrs_visible = true) {
    HkSymbolMap m;
    m.core_valid = (core_lo != 0 && core_hi > core_lo);
    m.core.lo = core_lo;
    m.core.hi = core_hi;
    m.core.owner.clear();
    m.sensitive_addr = std::move(syms);
    m.addrs_visible = addrs_visible;
    return m;
}
}  // namespace

// ===========================================================================
// SymbolMap parsers
// ===========================================================================
TEST(SymbolMap, IomemKernelCodeMatchedByName) {
    std::string iomem =
        "00000000-00000fff : Reserved\n"
        "ffffffff81000000-ffffffff81e00fff : Kernel code\n"
        "ffffffff81e01000-ffffffff8200ffff : Kernel data\n";
    TextRange core;
    ASSERT_TRUE(ParseIomemKernelCode(iomem, &core));
    EXPECT_EQ(core.lo, 0xffffffff81000000ull);
    EXPECT_EQ(core.hi, 0xffffffff81e01000ull);  // inclusive end + 1
}

TEST(SymbolMap, IomemZeroedAddrsAreCoverageGap) {
    std::string iomem = "00000000-00000000 : Kernel code\n";
    TextRange core;
    EXPECT_FALSE(ParseIomemKernelCode(iomem, &core));  // kptr_restrict zeroed
}

TEST(SymbolMap, KallsymsZeroedIsNotVisible) {
    // All sensitive addresses zeroed (kptr_restrict=2 without CAP_SYSLOG).
    std::string ks =
        "0000000000000000 T commit_creds\n"
        "0000000000000000 T prepare_kernel_cred\n";
    HkSymbolMap m;
    ASSERT_TRUE(ParseKallsymsSensitive(ks, &m));
    EXPECT_FALSE(m.addrs_visible);  // hidden → coverage gap, not drift
}

TEST(SymbolMap, KallsymsVisibleRetainsSensitiveOnly) {
    std::string ks =
        "ffffffff8128a0b0 T commit_creds\n"
        "ffffffff8128b000 T some_unrelated_fn\n"
        "ffffffff8128c000 t prepare_kernel_cred\n"
        "ffffffffc0a00000 T evil_fn\t[evil_mod]\n";  // module-attributed, ignored
    HkSymbolMap m;
    ASSERT_TRUE(ParseKallsymsSensitive(ks, &m));
    EXPECT_TRUE(m.addrs_visible);
    EXPECT_EQ(m.sensitive_addr.count("commit_creds"), 1u);
    EXPECT_EQ(m.sensitive_addr.count("prepare_kernel_cred"), 1u);
    EXPECT_EQ(m.sensitive_addr.count("some_unrelated_fn"), 0u);
}

// ===========================================================================
// 91 — kallsyms drift
// ===========================================================================
TEST(KallsymsAudit, CoverageGapEmitsUnavailableNotDrift) {
    ResetEvents();
    // addrs not visible → must be SENSOR_UNAVAILABLE(91), zero drift.
    HkSymbolMap m = MakeMap(0x1000, 0x2000, {{"commit_creds", 0}}, /*visible=*/false);
    AnalyzeKsym(m, CaptureSink);
    EXPECT_EQ(CountOfType(kEvtKsymDrift), 0);
    ASSERT_EQ(CountOfType(kEvtSensorUnavailable), 1);
}

TEST(KallsymsAudit, InBoundsSymbolNoDrift) {
    ResetEvents();
    HkSymbolMap m = MakeMap(0x1000, 0x9000, {{"commit_creds", 0x2000}});
    AnalyzeKsym(m, CaptureSink);
    EXPECT_EQ(CountOfType(kEvtKsymDrift), 0);
}

TEST(KallsymsAudit, OutOfBoundsSymbolFlagged) {
    ResetEvents();
    HkSymbolMap m = MakeMap(0x1000, 0x9000, {{"commit_creds", 0xDEAD0000}});
    AnalyzeKsym(m, CaptureSink);
    ASSERT_EQ(CountOfType(kEvtKsymDrift), 1);
}

TEST(KallsymsAudit, LivepatchShadowNotFlagged) {
    ResetEvents();
    // commit_creds relocated into a klp_ module .text — legitimate livepatch.
    HkSymbolMap m = MakeMap(0x1000, 0x9000, {{"commit_creds", 0x100000}});
    TextRange klp;
    klp.lo = 0x100000;
    klp.hi = 0x101000;
    klp.owner = "klp_vmlinux_fix";
    m.modules.push_back(klp);
    AnalyzeKsym(m, CaptureSink);
    EXPECT_EQ(CountOfType(kEvtKsymDrift), 0);  // allowlisted livepatch prefix
}

TEST(KallsymsAudit, NonLivepatchShadowFlagged) {
    ResetEvents();
    HkSymbolMap m = MakeMap(0x1000, 0x9000, {{"commit_creds", 0x200000}});
    TextRange evil;
    evil.lo = 0x200000;
    evil.hi = 0x201000;
    evil.owner = "rootkit";
    m.modules.push_back(evil);
    AnalyzeKsym(m, CaptureSink);
    ASSERT_EQ(CountOfType(kEvtKsymDrift), 1);
}

// ===========================================================================
// 93 — ftrace ownership
// ===========================================================================
TEST(FtraceAudit, UnreadableSourceEmitsUnavailable) {
    ResetEvents();
    HkSymbolMap m = MakeMap(0x1000, 0x9000, {});
    AnalyzeFtrace("", m, CaptureSink, /*source_readable=*/false);
    EXPECT_EQ(CountOfType(kEvtFtraceHook), 0);
    ASSERT_EQ(CountOfType(kEvtSensorUnavailable), 1);
}

TEST(FtraceAudit, ParsesEnabledFunctionsRowsAndOwner) {
    std::string ef =
        "commit_creds (1)\n"
        "\ttramp: 0xffffffffc0123000 (rootkit_hook+0x0)\n"
        "schedule (2)\n";
    auto rows = ParseEnabledFunctions(ef);
    ASSERT_GE(rows.size(), 2u);
    EXPECT_EQ(rows[0].func_name, "commit_creds");
    EXPECT_EQ(rows[0].ops_owner_addr, 0xffffffffc0123000ull);
}

TEST(FtraceAudit, HookOwnedByModuleIsAttributedNoFlag) {
    ResetEvents();
    // ops owner resolves inside a known module text → attributed → no client flag
    // (server decides allowlist).
    HkSymbolMap m = MakeMap(0x1000, 0x9000, {{"commit_creds", 0x2000}});
    TextRange mod;
    mod.lo = 0xc0100000;
    mod.hi = 0xc0200000;
    mod.owner = "datadog_agent";
    m.modules.push_back(mod);
    std::string ef = "commit_creds (1)\n\tops: 0xc0150000\n";
    AnalyzeFtrace(ef, m, CaptureSink, true);
    EXPECT_EQ(CountOfType(kEvtFtraceHook), 0);
}

TEST(FtraceAudit, HookWithUnattributableOwnerFlagged) {
    ResetEvents();
    HkSymbolMap m = MakeMap(0x1000, 0x9000, {{"commit_creds", 0x2000}});
    // ops owner 0xDEAD0000 resolves in NO known range → unattributed → flag.
    std::string ef = "commit_creds (1)\n\ttramp: 0xDEAD0000\n";
    AnalyzeFtrace(ef, m, CaptureSink, true);
    ASSERT_EQ(CountOfType(kEvtFtraceHook), 1);
}

TEST(FtraceAudit, NonSensitiveFunctionNotFlagged) {
    ResetEvents();
    HkSymbolMap m = MakeMap(0x1000, 0x9000, {});
    std::string ef = "schedule (1)\n\ttramp: 0xDEAD0000\n";
    AnalyzeFtrace(ef, m, CaptureSink, true);
    EXPECT_EQ(CountOfType(kEvtFtraceHook), 0);  // not in the sensitive set
}

// ===========================================================================
// 94 — kprobe placement
// ===========================================================================
TEST(KprobeAudit, ParsesListWithFlagsAndModule) {
    std::string list =
        "ffffffff8128a0b0  k  commit_creds+0x0    [OPTIMIZED]\n"
        "ffffffffc0a12000  r  prepare_kernel_cred+0x10  [DISABLED]  [evil_mod]\n";
    auto rows = ParseKprobeList(list);
    ASSERT_EQ(rows.size(), 2u);
    EXPECT_EQ(rows[0].symbol, "commit_creds");
    EXPECT_TRUE(rows[0].optimized);
    EXPECT_TRUE(rows[0].owner_module.empty());     // module-less
    EXPECT_EQ(rows[1].symbol, "prepare_kernel_cred");
    EXPECT_TRUE(rows[1].disabled);
    EXPECT_EQ(rows[1].owner_module, "evil_mod");
}

TEST(KprobeAudit, ModulelessSensitiveProbeFlaggedAsModuleless) {
    ResetEvents();
    HkSymbolMap m = MakeMap(0x1000, 0x9000, {});
    std::string list = "ffffffff8128a0b0  k  commit_creds+0x0  [OPTIMIZED]\n";
    AnalyzeKprobes(list, m, CaptureSink, true);
    ASSERT_EQ(CountOfType(kEvtKprobeSensitive), 1);
    HkEvtKprobeSensitive ev{};
    std::memcpy(&ev, g_events.back().payload.data(), sizeof(ev));
    EXPECT_TRUE((ev.flags & HK_KP_MODULELESS) != 0);
    EXPECT_EQ(ev.owner_signed, 0u);
}

TEST(KprobeAudit, UnreadableEmitsUnavailable) {
    ResetEvents();
    HkSymbolMap m = MakeMap(0x1000, 0x9000, {});
    AnalyzeKprobes("", m, CaptureSink, false);
    ASSERT_EQ(CountOfType(kEvtSensorUnavailable), 1);
    EXPECT_EQ(CountOfType(kEvtKprobeSensitive), 0);
}

// ===========================================================================
// 96 — posture
// ===========================================================================
TEST(LockdownPosture, ParsesActiveBracketLevel) {
    EXPECT_EQ(ParseLockdownLevel("[none] integrity confidentiality\n"), 0u);
    EXPECT_EQ(ParseLockdownLevel("none [integrity] confidentiality\n"), 1u);
    EXPECT_EQ(ParseLockdownLevel("none integrity [confidentiality]\n"), 2u);
    EXPECT_EQ(ParseLockdownLevel(""), HK_POSTURE_UNKNOWN);
}

TEST(LockdownPosture, SecureBootDecode) {
    std::string on = std::string("\x06\x00\x00\x00\x01", 5);
    std::string off = std::string("\x06\x00\x00\x00\x00", 5);
    EXPECT_EQ(ParseSecureBoot(on), 1u);
    EXPECT_EQ(ParseSecureBoot(off), 0u);
    EXPECT_EQ(ParseSecureBoot(""), HK_POSTURE_UNKNOWN);
}

TEST(LockdownPosture, AlwaysEmitsOnePostureWeightNeverDetection) {
    ResetEvents();
    // All-unknown posture must still emit exactly one posture event (a weight),
    // and zero detections.
    ComputePosture(HK_POSTURE_UNKNOWN, HK_POSTURE_UNKNOWN, HK_POSTURE_UNKNOWN, 0,
                   CaptureSink);
    ASSERT_EQ(CountOfType(kEvtKernelPosture), 1);
    EXPECT_EQ(CountOfType(kEvtKsymDrift), 0);
    EXPECT_EQ(CountOfType(kEvtSensorUnavailable), 0);
}

// ===========================================================================
// 92 — module view diff (debounce)
// ===========================================================================
TEST(ModuleViewDiff, AgreementNoFlag) {
    ResetEvents();
    ModuleViews v;
    v.proc_modules = {"nvidia", "ext4"};
    v.sysfs_modules = {"nvidia", "ext4"};
    ModuleViewDiffer d;
    d.Observe(v, CaptureSink, true, true);  // first snapshot, no emit
    d.Observe(v, CaptureSink, true, true);  // agree → no diff
    EXPECT_EQ(CountOfType(kEvtModuleViewDiff), 0);
}

TEST(ModuleViewDiff, PersistentProcGhostFlaggedAfterDebounce) {
    ResetEvents();
    // A module in /proc/modules but not /sys/module, persisting across two
    // snapshots → flag once (the asymmetry the list_del hide produces is the
    // mirror case; we exercise proc-only here for the debounce path).
    ModuleViews v;
    v.proc_modules = {"hidden_mod", "ext4"};
    v.sysfs_modules = {"ext4"};
    ModuleViewDiffer d;
    d.Observe(v, CaptureSink, true, true);
    d.Observe(v, CaptureSink, true, true);
    ASSERT_EQ(CountOfType(kEvtModuleViewDiff), 1);
}

TEST(ModuleViewDiff, TransientSingleSourceAbsorbedByDebounce) {
    ResetEvents();
    // Snapshot 1: discrepancy. Snapshot 2: resolved (agreement). Debounce must
    // absorb it → no flag.
    ModuleViews v1;
    v1.proc_modules = {"coming_mod", "ext4"};
    v1.sysfs_modules = {"ext4"};
    ModuleViews v2;
    v2.proc_modules = {"coming_mod", "ext4"};
    v2.sysfs_modules = {"coming_mod", "ext4"};
    ModuleViewDiffer d;
    d.Observe(v1, CaptureSink, true, true);
    d.Observe(v2, CaptureSink, true, true);
    EXPECT_EQ(CountOfType(kEvtModuleViewDiff), 0);
}

TEST(ModuleViewDiff, BothSourcesUnreadableIsCoverageGap) {
    ResetEvents();
    ModuleViews v;
    ModuleViewDiffer d;
    d.Observe(v, CaptureSink, false, false);
    ASSERT_EQ(CountOfType(kEvtSensorUnavailable), 1);
    EXPECT_EQ(CountOfType(kEvtModuleViewDiff), 0);
}

// ===========================================================================
// 95 — module disk drift (build-id)
// ===========================================================================
TEST(ModuleDiskDrift, BuildIdNoteParse) {
    // namesz=4, descsz=4, type=3, "GNU\0", desc=DEADBEEF
    std::string note;
    auto put32 = [&](uint32_t v) {
        note.append(reinterpret_cast<const char*>(&v), 4);
    };
    put32(4);
    put32(4);
    put32(3);
    note.append("GNU\0", 4);
    note.append("\xDE\xAD\xBE\xEF", 4);
    auto id = ParseBuildIdNote(note);
    ASSERT_EQ(id.size(), 4u);
    EXPECT_EQ(id[0], 0xDE);
}

TEST(ModuleDiskDrift, MatchNoFlag_MismatchFlag_NoDiskFlag) {
    ResetEvents();
    std::vector<uint8_t> a = {1, 2, 3, 4};
    std::vector<uint8_t> b = {1, 2, 3, 4};
    std::vector<uint8_t> c = {9, 9, 9, 9};

    // match → no flag
    EXPECT_EQ(AnalyzeModuleDisk("ext4", a, b, true, CaptureSink), 0);
    EXPECT_EQ(CountOfType(kEvtModuleDiskDrift), 0);

    // mismatch → flag (substitution)
    EXPECT_EQ(AnalyzeModuleDisk("ext4", a, c, true, CaptureSink), 1);
    ASSERT_EQ(CountOfType(kEvtModuleDiskDrift), 1);

    ResetEvents();
    // no backing .ko → flag (NO_DISK_KO)
    EXPECT_EQ(AnalyzeModuleDisk("rootkit", a, {}, false, CaptureSink), 1);
    ASSERT_EQ(CountOfType(kEvtModuleDiskDrift), 1);
    HkEvtModuleDiskDrift ev{};
    std::memcpy(&ev, g_events.back().payload.data(), sizeof(ev));
    EXPECT_EQ(ev.reason, static_cast<uint32_t>(HK_MD_NO_DISK_KO));
}

TEST(ModuleDiskDrift, DkmsRebuildConsistentNoFlag) {
    ResetEvents();
    // A DKMS rebuild changes the build-id, but it changes BOTH memory and disk
    // together — same file, consistent ids → no flag.
    std::vector<uint8_t> rebuilt = {0xAB, 0xCD};
    EXPECT_EQ(AnalyzeModuleDisk("nvidia", rebuilt, rebuilt, true, CaptureSink), 0);
    EXPECT_EQ(CountOfType(kEvtModuleDiskDrift), 0);
}

TEST(ModuleDiskDrift, UnreadableMemBuildIdSkipped) {
    ResetEvents();
    // In-memory build-id unreadable → coverage gap, skip (no drift).
    EXPECT_EQ(AnalyzeModuleDisk("x", {}, {1, 2}, true, CaptureSink), 0);
    EXPECT_EQ(CountOfType(kEvtModuleDiskDrift), 0);
}

// ===========================================================================
// 97 — foreign BPF classifier
// ===========================================================================
TEST(BpfEnumerate, ForeignProgOnProtectedTargetFlagged) {
    BpfClientIdentity id;
    id.protected_targets = {"commit_creds"};
    id.own_tags = {0x1111};
    BpfProgRecord prog;
    prog.id = 42;
    prog.type = 5;
    prog.tag = 0x9999;  // not ours
    prog.attach_target = "commit_creds";
    HkEvtForeignBpf out{};
    EXPECT_TRUE(ClassifyBpfProg(prog, id, &out));
    EXPECT_EQ(out.prog_id, 42u);
    EXPECT_EQ(out.prog_tag_hash, 0x9999ull);
}

TEST(BpfEnumerate, OwnTagNotFlagged) {
    BpfClientIdentity id;
    id.protected_targets = {"commit_creds"};
    id.own_tags = {0x1111};
    BpfProgRecord prog;
    prog.tag = 0x1111;  // our own program
    prog.attach_target = "commit_creds";
    HkEvtForeignBpf out{};
    EXPECT_FALSE(ClassifyBpfProg(prog, id, &out));
}

TEST(BpfEnumerate, ProgOnNonProtectedTargetNotFlagged) {
    BpfClientIdentity id;
    id.protected_targets = {"commit_creds"};
    BpfProgRecord prog;
    prog.tag = 0x9999;
    prog.attach_target = "schedule";  // not a protected hook point
    HkEvtForeignBpf out{};
    EXPECT_FALSE(ClassifyBpfProg(prog, id, &out));
}

TEST(BpfEnumerate, SystemdAllowlistedNotFlagged) {
    BpfClientIdentity id;
    id.protected_targets = {"commit_creds"};
    id.systemd_allowlist_tags = {0x7777};
    BpfProgRecord prog;
    prog.tag = 0x7777;
    prog.attach_target = "commit_creds";
    HkEvtForeignBpf out{};
    EXPECT_FALSE(ClassifyBpfProg(prog, id, &out));
}

// ===========================================================================
// 99 — MSR path / index resolver
// ===========================================================================
TEST(MsrPathResolver, SensitiveMsrIndices) {
    EXPECT_TRUE(IsSensitiveMsr(0xC0000082));  // LSTAR
    EXPECT_TRUE(IsSensitiveMsr(0x00000176));  // SYSENTER_EIP
    EXPECT_FALSE(IsSensitiveMsr(0x150));      // power/perf — benign
    EXPECT_FALSE(IsSensitiveMsr(0x199));
    EXPECT_FALSE(IsSensitiveMsr(0x1A0));
}

TEST(MsrPathResolver, FdTargetMsrMatch) {
    EXPECT_TRUE(FdTargetIsMsr("/dev/cpu/0/msr"));
    EXPECT_TRUE(FdTargetIsMsr("/dev/cpu/15/msr"));
    EXPECT_FALSE(FdTargetIsMsr("/dev/cpu/0/cpuid"));
    EXPECT_FALSE(FdTargetIsMsr("/dev/cpu//msr"));      // empty index
    EXPECT_FALSE(FdTargetIsMsr("/dev/mem"));
    EXPECT_FALSE(FdTargetIsMsr("/dev/cpu/x/msr"));     // non-digit index
}

// ===========================================================================
// Name hashing — non-reversible, stable
// ===========================================================================
TEST(HostIntegrity, NameHashStableAndNonZero) {
    EXPECT_EQ(HkNameHash("nvidia"), HkNameHash("nvidia"));
    EXPECT_NE(HkNameHash("nvidia"), HkNameHash("ext4"));
    EXPECT_NE(HkNameHash("nvidia"), 0u);
}
