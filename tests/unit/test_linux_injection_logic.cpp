/*
 * tests/unit/test_linux_injection_logic.cpp
 * Role: Host-runnable pure-logic tests for the linux-ebpf-injection correlators
 *       (signals 82-90). The correlator decision cores + ElfModel /proc parsing +
 *       OverlayAllowlist signature/lookup are plain C++17 (no libbpf, no
 *       Linux-only syscalls in the tested paths) so they run above the platform
 *       guard via an injected fixture ProcReader. Covers the FP-suppression
 *       half of each signal (allowlisted overlay → no event; IFUNC slot → no
 *       event; tracer-attached → suppressed; manifest-resolved interp → no event;
 *       steady-state preload → no event) which is the load-bearing part.
 * Target platforms: host (build box).
 * Interface: gtest; compiles the correlator .cpp sources directly (see
 *            tests/unit/CMakeLists.txt).
 */

#include <gtest/gtest.h>

#include <cstring>
#include <map>
#include <string>
#include <utility>
#include <vector>

#include "DlopenBacking.h"
#include "DsoProvenance.h"
#include "ElfModel.h"
#include "GotPltMap.h"
#include "InterpCheck.h"
#include "LinkMapOrder.h"
#include "OverlayAllowlist.h"
#include "PreloadWatch.h"
#include "RDebugCheck.h"
#include "TextPageBacking.h"

using namespace horkos;

// ---- Fixture ProcReader ----------------------------------------------------
namespace {
class FakeProc final : public elfmodel::ProcReader {
public:
    std::map<std::pair<uint32_t, std::string>, std::string> text;
    std::map<std::pair<uint32_t, std::string>, std::vector<uint8_t>> bytes;

    std::optional<std::string> ReadText(uint32_t pid,
                                        const std::string& name) const override {
        auto it = text.find({pid, name});
        if (it == text.end()) return std::nullopt;
        return it->second;
    }
    std::vector<uint8_t> ReadBytes(uint32_t pid, const std::string& name, uint64_t,
                                   size_t) const override {
        auto it = bytes.find({pid, name});
        if (it == bytes.end()) return {};
        return it->second;
    }
};

// A trivially-trusting verifier for tests; production uses Ed25519/ECDSA.
allowlist::OverlayAllowlist MakeAllowlist(const std::string& body_text) {
    allowlist::OverlayAllowlist a;
    std::vector<uint8_t> body(body_text.begin(), body_text.end());
    std::vector<uint8_t> sig = {1};  // non-empty
    a.LoadSigned(body, sig, [](const std::vector<uint8_t>&,
                               const std::vector<uint8_t>& s) { return !s.empty(); });
    return a;
}
}  // namespace

// ---- ElfModel: maps parsing + backing classification -----------------------
TEST(ElfModel, MapsBackingClassification) {
    std::string maps =
        "55a000-55b000 r-xp 00000000 fd:00 12345 /usr/lib/libfoo.so\n"
        "7f0000-7f1000 r-xp 00000000 00:00 0 \n"
        "7f2000-7f3000 r-xp 00000000 fd:00 99 /tmp/evil.so (deleted)\n"
        "7f4000-7f5000 rwxp 00000000 00:05 7 /memfd:jit (deleted)\n"
        "7f6000-7f7000 r--p 00000000 fd:00 1 /usr/lib/librelro.so\n";
    auto v = elfmodel::ParseMaps(maps);
    ASSERT_EQ(v.size(), 5u);
    EXPECT_EQ(v[0].backing, elfmodel::MapBacking::kFileBacked);
    EXPECT_TRUE(v[0].executable);
    EXPECT_EQ(v[1].backing, elfmodel::MapBacking::kAnonymous);
    EXPECT_EQ(v[2].backing, elfmodel::MapBacking::kDeleted);
    EXPECT_EQ(v[2].path, "/tmp/evil.so");
    EXPECT_EQ(v[3].backing, elfmodel::MapBacking::kMemfd);
    EXPECT_TRUE(v[3].writable && v[3].executable);
    EXPECT_FALSE(v[4].executable);
    EXPECT_FALSE(v[4].writable);  // RELRO r--p
}

TEST(ElfModel, FindExecVmaForAddr) {
    auto v = elfmodel::ParseMaps(
        "1000-2000 r-xp 0 fd:00 1 /a\n3000-4000 rw-p 0 fd:00 2 /b\n");
    EXPECT_TRUE(elfmodel::FindExecVmaForAddr(v, 0x1500).has_value());
    EXPECT_FALSE(elfmodel::FindExecVmaForAddr(v, 0x3500).has_value());  // not exec
    EXPECT_FALSE(elfmodel::FindExecVmaForAddr(v, 0x9999).has_value());
}

TEST(ElfModel, BuildIdPrefix) {
    std::vector<uint8_t> id = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09};
    EXPECT_EQ(elfmodel::BuildIdPrefix(id), 0x0807060504030201ull);
    EXPECT_EQ(elfmodel::BuildIdPrefix({0x01, 0x02}), 0u);  // too short
}

// ---- OverlayAllowlist: verify-before-use + lookup --------------------------
TEST(OverlayAllowlist, TamperRejectLeavesEmpty) {
    allowlist::OverlayAllowlist a;
    std::vector<uint8_t> body = {'x'};
    std::vector<uint8_t> sig = {};  // empty → our test verifier rejects
    EXPECT_FALSE(a.LoadSigned(body, sig, [](const std::vector<uint8_t>&,
                                            const std::vector<uint8_t>& s) {
        return !s.empty();
    }));
    EXPECT_FALSE(a.verified());
    EXPECT_FALSE(a.IsAllowed("libMangoHud.so", {}, "deck"));  // nothing allowed
}

TEST(OverlayAllowlist, SonameAnyBuildAndScoped) {
    auto a = MakeAllowlist(
        "# overlay allowlist\n"
        "libMangoHud.so * *\n"
        "libjemalloc.so 0102030405060708 deck\n");
    EXPECT_TRUE(a.verified());
    EXPECT_TRUE(a.IsAllowed("libMangoHud.so", {}, "any-scope"));
    // jemalloc only allowed with exact build-id under deck scope.
    std::vector<uint8_t> bid = {1, 2, 3, 4, 5, 6, 7, 8};
    EXPECT_TRUE(a.IsAllowed("libjemalloc.so", bid, "deck"));
    EXPECT_FALSE(a.IsAllowed("libjemalloc.so", bid, "ubuntu"));  // wrong scope
    EXPECT_FALSE(a.IsAllowed("libjemalloc.so", {9, 9}, "deck"));  // wrong build
    EXPECT_FALSE(a.IsAllowed("libevil.so", {}, "deck"));
}

// ---- Signal 82: DSO provenance ---------------------------------------------
TEST(DsoProvenance, OutsideClosureAndAllowlistFires) {
    FakeProc proc;
    auto allow = MakeAllowlist("libMangoHud.so * *\n");
    inject::DsoProvenance d(proc, allow, "deck");

    // No exe bytes → AttachPid fails gracefully; closure empty.
    EXPECT_FALSE(d.AttachPid(42));

    inject::DsoMapEvent ev;
    ev.pid = 42;
    ev.soname = "libcheat.so";
    ev.resolved_path = "/tmp/libcheat.so";
    inject::InjectionFinding out;
    EXPECT_TRUE(d.OnMapEvent(ev, &out));
    EXPECT_EQ(out.event_type, inject::kEvtDsoProvenance);
    EXPECT_TRUE(out.flags & inject::HK_DSO_FLAG_NO_DT_NEEDED);
    EXPECT_TRUE(out.flags & inject::HK_DSO_FLAG_OUTSIDE_ALLOW);
}

TEST(DsoProvenance, AllowlistedOverlaySuppressed) {
    FakeProc proc;
    auto allow = MakeAllowlist("libMangoHud.so * *\n");
    inject::DsoProvenance d(proc, allow, "deck");
    inject::DsoMapEvent ev;
    ev.pid = 7;
    ev.soname = "libMangoHud.so";
    ev.resolved_path = "/usr/lib/libMangoHud.so";
    inject::InjectionFinding out;
    EXPECT_FALSE(d.OnMapEvent(ev, &out));  // allowlisted → suppressed
}

// ---- Signal 87: load-order inversion (corroborating-only) ------------------
TEST(LinkMapOrder, InterposerPrecedingLibcFlagged) {
    auto allow = MakeAllowlist("libjemalloc.so * *\n");
    inject::LinkMapOrder lo(allow, "deck");

    // A non-provenanced malloc interposer mapped at index 1 (before libc).
    inject::DsoMapEvent evil;
    evil.pid = 5;
    evil.soname = "libhook.so";
    evil.link_map_index = 1;
    inject::InjectionFinding out;
    EXPECT_TRUE(lo.OnMapEvent(evil, /*has_dt_needed=*/false, {"malloc"},
                              /*is_canonical_libc=*/false, &out));
    EXPECT_EQ(out.event_type, inject::kEvtLoadorderInvert);

    // jemalloc (allowlisted) interposing malloc → suppressed.
    inject::DsoMapEvent jem;
    jem.pid = 6;
    jem.soname = "libjemalloc.so";
    jem.link_map_index = 1;
    EXPECT_FALSE(lo.OnMapEvent(jem, false, {"malloc"}, false, &out));
}

// ---- Signal 86: fileless dlopen --------------------------------------------
TEST(DlopenBacking, MemfdExecFiresFileBackedSuppressed) {
    FakeProc proc;
    auto allow = MakeAllowlist("");
    proc.text[{10, "maps"}] =
        "1000-2000 r-xp 0 00:05 7 /memfd:payload (deleted)\n"
        "3000-4000 r-xp 0 fd:00 1 /usr/lib/libc.so.6\n";
    inject::DlopenBacking db(proc, allow, "deck");

    inject::DlopenEvent ev;
    ev.pid = 10;
    ev.path = "/proc/self/fd/5";
    inject::InjectionFinding out;
    EXPECT_TRUE(db.OnDlopen(ev, &out));
    EXPECT_EQ(out.event_type, inject::kEvtDlopenBacking);

    // A purely file-backed process → no fileless exec mapping → no event.
    proc.text[{11, "maps"}] = "3000-4000 r-xp 0 fd:00 1 /usr/lib/libgconv.so\n";
    inject::DlopenEvent ev2;
    ev2.pid = 11;
    ev2.path = "/usr/lib/libgconv.so";
    EXPECT_FALSE(db.OnDlopen(ev2, &out));
}

// ---- Signal 85: transient preload ------------------------------------------
TEST(PreloadWatch, TransientEnvFiresSteadyStateSuppressed) {
    auto allow = MakeAllowlist("");
    inject::PreloadWatch pw(allow, "deck");
    pw.SetSteadyStatePreload("# system preloads\n/usr/lib/libsystem-preload.so\n");

    // LD_PRELOAD at exec NOT in the steady-state file → transient injection.
    inject::BprmEnvEvent ev;
    ev.pid = 20;
    ev.env_flags = inject::HK_ENV_LD_PRELOAD;
    ev.ancestor_pid = 19;
    ev.ld_preload_value = "/tmp/cheat.so";
    inject::InjectionFinding out;
    EXPECT_TRUE(pw.OnExecEnv(ev, &out));
    EXPECT_EQ(out.event_type, inject::kEvtPreloadAnomaly);
    EXPECT_EQ(out.detail, 19u);  // ancestor attribution

    // Same module listed in steady-state → persistent, not transient → suppressed.
    inject::BprmEnvEvent ev2 = ev;
    ev2.ld_preload_value = "/usr/lib/libsystem-preload.so";
    EXPECT_FALSE(pw.OnExecEnv(ev2, &out));
}

// ---- Signal 88: _r_debug r_brk ---------------------------------------------
TEST(RDebugCheck, ForeignRbrkFiresTracerSuppressed) {
    FakeProc proc;
    proc.text[{30, "maps"}] =
        "100000-101000 r-xp 0 fd:00 1 /usr/lib/ld-linux-x86-64.so.2\n";
    inject::RDebugCheck rc(proc);

    // r_brk pointing OUTSIDE the ld.so range, no tracer → fires.
    inject::RdebugTickEvent ev;
    ev.pid = 30;
    ev.r_brk = 0x500000;  // outside ld.so VMA
    ev.tracer_attached = false;
    inject::InjectionFinding out;
    EXPECT_TRUE(rc.OnTick(ev, &out));
    EXPECT_EQ(out.event_type, inject::kEvtRdebugAnomaly);

    // Same, but a tracer is attached → suppressed.
    ev.tracer_attached = true;
    EXPECT_FALSE(rc.OnTick(ev, &out));

    // r_brk INSIDE ld.so → normal, no event.
    inject::RdebugTickEvent ok;
    ok.pid = 30;
    ok.r_brk = 0x100500;
    EXPECT_FALSE(rc.OnTick(ok, &out));
}

// ---- Signal 83: GOT/PLT redirect -------------------------------------------
TEST(GotPltMap, RwxTargetFiresIfuncAndLazySuppressed) {
    auto allow = MakeAllowlist("");
    inject::GotPltMap g(allow, "deck");
    auto vmas = elfmodel::ParseMaps(
        "400000-401000 r-xp 0 fd:00 1 /game\n"      // own .text/.plt
        "500000-501000 rwxp 0 00:00 0 \n"            // anon RWX trampoline
        "600000-601000 r-xp 0 fd:00 2 /usr/lib/libc.so.6\n");

    inject::GotSampleEvent ev;
    ev.pid = 40;
    ev.own_plt_start = 0x400000;
    ev.own_plt_end = 0x401000;
    // slot 0: IFUNC pointing into RWX — must be SKIPPED (is_ifunc true).
    // slot 1: points into own PLT (lazy, unresolved) — benign.
    // slot 2: points into anon RWX — ANOMALY.
    ev.slot_target = {0x500800, 0x400400, 0x500900};
    ev.is_ifunc = {true, false, false};
    inject::InjectionFinding out;
    EXPECT_TRUE(g.OnSample(ev, vmas, &out));
    EXPECT_EQ(out.event_type, inject::kEvtGotAnomaly);
    EXPECT_EQ(out.detail, 0x500900u);

    // A sample whose only non-IFUNC, non-lazy slot points into libc (r-x,
    // file-backed) → benign, no event.
    inject::GotSampleEvent ok;
    ok.pid = 40;
    ok.own_plt_start = 0x400000;
    ok.own_plt_end = 0x401000;
    ok.slot_target = {0x600400};
    ok.is_ifunc = {false};
    EXPECT_FALSE(g.OnSample(ok, vmas, &out));
}

// ---- Signal 90: text COW-broken --------------------------------------------
TEST(TextPageBacking, ParseAndDirtyFires) {
    std::string smaps =
        "400000-401000 r-xp 00000000 fd:00 1 /game\n"
        "Size:                  4 kB\n"
        "Private_Dirty:         4 kB\n"
        "500000-501000 r-xp 00000000 fd:00 2 /usr/lib/libc.so.6\n"
        "Private_Dirty:         0 kB\n";
    auto vmas = inject::TextPageBacking::ParseExecSmaps(smaps);
    ASSERT_EQ(vmas.size(), 2u);
    EXPECT_EQ(vmas[0].private_dirty_kb, 4u);
    EXPECT_TRUE(vmas[0].file_backed);

    inject::TextPageBacking t;
    inject::TextTickEvent ev;
    ev.pid = 50;
    inject::InjectionFinding out;
    EXPECT_TRUE(t.OnTick(ev, vmas, {}, &out));  // libc clean, /game dirty → fires
    EXPECT_EQ(out.detail, 0x400000u);

    // Tracer attached → suppressed.
    ev.tracer_attached = true;
    EXPECT_FALSE(t.OnTick(ev, vmas, {}, &out));

    // Dirty page fully inside an allowed IFUNC/reloc span → suppressed.
    ev.tracer_attached = false;
    std::vector<std::pair<uint64_t, uint64_t>> allowed = {{0x400000, 0x401000}};
    EXPECT_FALSE(t.OnTick(ev, vmas, allowed, &out));
}

// ---- Signal 84: PT_INTERP mismatch -----------------------------------------
namespace {
std::vector<std::vector<uint8_t>> AcceptVesselLoader(uint32_t, void*) {
    return {{0xAA, 0xBB, 0xCC, 0xDD}};  // the accepted pressure-vessel ld.so build-id
}
}  // namespace

TEST(InterpCheck, ManifestResolvedSuppressed) {
    // Build a tiny ELF with a NT_GNU_BUILD_ID note so ParseBuildId can read it.
    // Header (64) + 1 section header (.note) + shstrtab. Simpler: craft via the
    // ElfModel note-walk expectations is heavy; instead assert the suppression
    // branch using a build-id that matches the manifest by feeding the interp
    // bytes whose ParseBuildId yields the accepted id.
    FakeProc proc;
    proc.text[{60, "maps"}] =
        "100000-101000 r-xp 0 fd:00 1 /steam/pressure-vessel/ld.so\n";

    // Construct a minimal ELF blob carrying NT_GNU_BUILD_ID = AA BB CC DD.
    std::vector<uint8_t> elf(64, 0);
    elf[0] = 0x7f; elf[1] = 'E'; elf[2] = 'L'; elf[3] = 'F';
    elf[4] = 2; elf[5] = 1;  // ELFCLASS64, LSB
    // e_shoff @40 = 64, e_shentsize @58 = 64, e_shnum @60 = 2, e_shstrndx @62 = 1
    uint64_t shoff = 64;
    std::memcpy(&elf[40], &shoff, 8);
    uint16_t shentsize = 64, shnum = 2, shstrndx = 1;
    std::memcpy(&elf[58], &shentsize, 2);
    std::memcpy(&elf[60], &shnum, 2);
    std::memcpy(&elf[62], &shstrndx, 2);

    // Section 0: the NOTE section. Build the note payload first.
    // note: namesz=4 ("GNU\0"), descsz=4 (AA BB CC DD), type=3
    std::vector<uint8_t> note = {4,0,0,0, 4,0,0,0, 3,0,0,0,
                                 'G','N','U',0, 0xAA,0xBB,0xCC,0xDD};
    // Lay out: [64-byte ehdr][shdr0 64][shdr1 64][shstrtab][note]
    size_t sh0_off = 64, sh1_off = 128, strtab_off = 192, note_off = 256;
    elf.resize(note_off + note.size(), 0);
    std::string shstr = std::string("\0.note\0", 7);  // index 1 -> ".note"
    for (size_t i = 0; i < shstr.size(); ++i) elf[strtab_off + i] = (uint8_t)shstr[i];

    auto put_shdr = [&](size_t base, uint32_t name, uint32_t type, uint64_t off,
                        uint64_t size) {
        std::memcpy(&elf[base + 0], &name, 4);
        std::memcpy(&elf[base + 4], &type, 4);
        std::memcpy(&elf[base + 24], &off, 8);   // sh_offset
        std::memcpy(&elf[base + 32], &size, 8);  // sh_size
    };
    put_shdr(sh0_off, 1 /*".note"*/, 7 /*SHT_NOTE*/, note_off, note.size());
    put_shdr(sh1_off, 0, 3 /*STRTAB*/, strtab_off, shstr.size());
    for (size_t i = 0; i < note.size(); ++i) elf[note_off + i] = note[i];

    EXPECT_EQ(elfmodel::ParseBuildId(elf),
              (std::vector<uint8_t>{0xAA, 0xBB, 0xCC, 0xDD}));

    proc.bytes[{60, "map_files/interp"}] = elf;

    inject::InterpCheck ic(proc, &AcceptVesselLoader, nullptr);
    inject::InterpEvent ev;
    ev.pid = 60;
    ev.entry_ip = 0x100400;  // inside the mapped ld.so
    inject::InjectionFinding out;
    // build-id matches the manifest's accepted set → suppressed.
    EXPECT_FALSE(ic.OnInterp(ev, /*expected_host=*/{}, &out));

    // A different host loader whose build-id is NOT accepted → fires.
    inject::InterpCheck ic2(proc, nullptr, nullptr);  // no manifest
    EXPECT_TRUE(ic2.OnInterp(ev, /*expected_host=*/{0x11, 0x22}, &out));
    EXPECT_EQ(out.event_type, inject::kEvtInterpMismatch);
}
