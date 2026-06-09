/*
 * tests/unit/test_render_hook_logic.cpp
 * Role: Host-runnable unit tests for the PLATFORM-FREE decision cores of the
 *       win-usermode-overlay render sensors (catalog signals 46-54). Exercises the
 *       pure provenance classifier, window-style folding, and rect-overlap helpers
 *       from RenderSensorWin.h, the schema size guard from render_hook_schema.h, and
 *       the PE export/relocation math from PeRelocate.h — all with no live process
 *       and no Win32 (the headers' platform-touching declarations are #if-guarded
 *       out on this host).
 * Target platforms: all (host unit test; no Windows headers pulled in).
 * Interface: drives hk::sdk::render::* pure cores and hk::sdk::pe::* PE math.
 */

#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <vector>

/* The render-sensor façade's pure cores live above the HK_PLATFORM_WINDOWS guard,
 * so this header is includable on the host without Win32. */
#include "backends/win/RenderSensorWin.h"
#include "backends/win/PeRelocate.h"
#include "horkos/render_hook_schema.h"

using namespace hk::sdk::render;

/* -------------------------------------------------------------------------
 * Schema size guard. The HK_STATIC_ASSERT in the header is the compile-time pin;
 * this runtime check additionally documents the 56-byte contract the Rust mirror
 * (server/telemetry/src/render_hook.rs) tracks.
 * ------------------------------------------------------------------------- */
TEST(RenderSchema, FindingIsFortyEightBytes) {
    /* 6 x uint32 + 3 x 64-bit, no tail padding. The C header pins this with
     * HK_STATIC_ASSERT; the Rust mirror tracks the same numeric core. */
    EXPECT_EQ(sizeof(hk_render_finding), 48u);
}

/* -------------------------------------------------------------------------
 * Provenance classifier (signals 46/47/52/54). Table-driven over the decision
 * surface, including the HK_PROV_UNRESOLVED guard when VirtualQuery fails.
 * ------------------------------------------------------------------------- */
TEST(Provenance, UnresolvedBackingIsUnresolved) {
    ProvenanceInput in{};
    in.backing = TargetBacking::Unresolved;
    EXPECT_EQ(classify_provenance(in), HK_PROV_UNRESOLVED);
}

TEST(Provenance, PrivateExecutableIsPrivateRx) {
    ProvenanceInput in{};
    in.backing = TargetBacking::Private;
    in.in_known_module = false;
    EXPECT_EQ(classify_provenance(in), HK_PROV_PRIVATE_RX);
}

TEST(Provenance, MappedDataExecutableIsPrivateRx) {
    /* MEM_MAPPED (non-image) executable target is the same strong tampering shape
     * as private RX: legitimate present-path code is MEM_IMAGE. */
    ProvenanceInput in{};
    in.backing = TargetBacking::Mapped;
    in.in_known_module = false;
    EXPECT_EQ(classify_provenance(in), HK_PROV_PRIVATE_RX);
}

TEST(Provenance, ImageBackedButOutsideKnownModuleIsPrivateRx) {
    ProvenanceInput in{};
    in.backing = TargetBacking::Image;
    in.in_known_module = false; /* image bit set but not resolved to a map entry */
    EXPECT_EQ(classify_provenance(in), HK_PROV_PRIVATE_RX);
}

TEST(Provenance, ImageUnsignedModule) {
    ProvenanceInput in{};
    in.backing = TargetBacking::Image;
    in.in_known_module = true;
    in.module_signed = false;
    EXPECT_EQ(classify_provenance(in), HK_PROV_IMAGE_UNSIGNED);
}

TEST(Provenance, ImageSignedForeignModule) {
    ProvenanceInput in{};
    in.backing = TargetBacking::Image;
    in.in_known_module = true;
    in.module_signed = true;
    in.module_allowlisted = false;
    EXPECT_EQ(classify_provenance(in), HK_PROV_IMAGE_SIGNED_FOREIGN);
}

TEST(Provenance, ImageSignedAllowlistedModule) {
    ProvenanceInput in{};
    in.backing = TargetBacking::Image;
    in.in_known_module = true;
    in.module_signed = true;
    in.module_allowlisted = true;
    EXPECT_EQ(classify_provenance(in), HK_PROV_IMAGE_SIGNED_ALLOWLISTED);
}

/* -------------------------------------------------------------------------
 * Window-style folding + rect overlap (signals 49/51).
 * ------------------------------------------------------------------------- */
TEST(WindowStyle, FoldsExStyleBits) {
    WindowStyleInput in{};
    in.ws_ex_layered = true;
    in.ws_ex_topmost = true;
    in.ws_ex_noactivate = true;
    in.dwm_cloaked = true;
    const uint32_t bits = fold_window_style(in);
    EXPECT_TRUE(bits & HK_WSTYLE_LAYERED);
    EXPECT_TRUE(bits & HK_WSTYLE_TOPMOST);
    EXPECT_TRUE(bits & HK_WSTYLE_NOACTIVATE);
    EXPECT_TRUE(bits & HK_WSTYLE_CLOAKED);
    EXPECT_FALSE(bits & HK_WSTYLE_TRANSPARENT);
}

TEST(WindowStyle, ClickThroughRequiresTransparentAndPerPixelAlpha) {
    WindowStyleInput in{};
    in.ws_ex_transparent = true;
    in.per_pixel_alpha = true;
    EXPECT_TRUE(fold_window_style(in) & HK_WSTYLE_CLICKTHROUGH);

    /* Transparent alone (no per-pixel alpha) is not the derived click-through. */
    WindowStyleInput only_transparent{};
    only_transparent.ws_ex_transparent = true;
    EXPECT_FALSE(fold_window_style(only_transparent) & HK_WSTYLE_CLICKTHROUGH);

    /* Per-pixel alpha without the transparent hit-test bit is not click-through. */
    WindowStyleInput only_alpha{};
    only_alpha.per_pixel_alpha = true;
    EXPECT_FALSE(fold_window_style(only_alpha) & HK_WSTYLE_CLICKTHROUGH);
}

TEST(RectOverlap, OverlappingRectsReportTrue) {
    Rect a{0, 0, 100, 100};
    Rect b{50, 50, 150, 150};
    EXPECT_TRUE(rects_overlap(a, b));
    EXPECT_TRUE(rects_overlap(b, a));
}

TEST(RectOverlap, DisjointRectsReportFalse) {
    Rect a{0, 0, 100, 100};
    Rect b{100, 100, 200, 200}; /* edge-touching: right/bottom exclusive => no area */
    EXPECT_FALSE(rects_overlap(a, b));

    Rect c{200, 200, 300, 300};
    EXPECT_FALSE(rects_overlap(a, c));
}

TEST(RectOverlap, EmptyRectNeverOverlaps) {
    Rect empty{10, 10, 10, 10};
    Rect big{0, 0, 100, 100};
    EXPECT_FALSE(rects_overlap(empty, big));
}

/* -------------------------------------------------------------------------
 * PE export + relocation math (PeRelocate.h, signal 47). A synthetic minimal
 * PE32+ image with one section, one named export, and a single DIR64 relocation
 * inside the export prologue. Asserts the export RVA resolves and a relocated
 * absolute pointer is rewritten to the live-base value (so an ASLR relocation is
 * not misread as a patch — the catalog FP guard).
 * ------------------------------------------------------------------------- */
namespace {

/* Little-endian writers into a flat buffer. */
void put16(std::vector<uint8_t>& b, size_t off, uint16_t v) {
    b[off] = static_cast<uint8_t>(v & 0xFF);
    b[off + 1] = static_cast<uint8_t>((v >> 8) & 0xFF);
}
void put32(std::vector<uint8_t>& b, size_t off, uint32_t v) {
    for (int i = 0; i < 4; ++i) b[off + i] = static_cast<uint8_t>((v >> (8 * i)) & 0xFF);
}
void put64(std::vector<uint8_t>& b, size_t off, uint64_t v) {
    for (int i = 0; i < 8; ++i) b[off + i] = static_cast<uint8_t>((v >> (8 * i)) & 0xFF);
}

/* Build a minimal PE32+ image. Layout (all in one .text section mapped 1:1 so
 * RVA == file offset, which the section table below declares):
 *   - DOS header (e_lfanew at 0x3C -> 0x80)
 *   - NT signature + IMAGE_FILE_HEADER + IMAGE_OPTIONAL_HEADER64 (+ data dirs)
 *   - one IMAGE_SECTION_HEADER
 *   - export directory + name/ordinal/function tables + export name string
 *   - a base-relocation block with one DIR64 fixup
 * Returns the bytes; fills out the RVAs the test asserts on. */
struct SynthPe {
    std::vector<uint8_t> bytes;
    uint32_t export_rva = 0;        /* RVA of the exported function prologue */
    uint32_t reloc_target_rva = 0;  /* RVA of the 8-byte DIR64 fixup */
    uint64_t preferred_base = 0x140000000ull;
    uint64_t original_pointer = 0;  /* absolute value stored at the fixup on disk */
};

SynthPe build_synth_pe() {
    SynthPe pe;
    pe.bytes.assign(0x800, 0);
    auto& b = pe.bytes;

    const uint32_t e_lfanew = 0x80;
    put16(b, 0x00, 0x5A4D);          /* 'MZ' */
    put32(b, 0x3C, e_lfanew);

    put32(b, e_lfanew, 0x00004550);  /* 'PE\0\0' */
    const uint32_t file_hdr = e_lfanew + 4;
    put16(b, file_hdr + 2, 1);       /* NumberOfSections = 1 */
    const uint16_t opt_size = 240;   /* SizeOfOptionalHeader (PE32+ incl. 16 dirs) */
    put16(b, file_hdr + 16, opt_size);

    const uint32_t opt_hdr = file_hdr + 20;
    put16(b, opt_hdr, 0x020B);       /* PE32+ magic */
    put64(b, opt_hdr + 24, pe.preferred_base); /* ImageBase */
    const uint32_t dir_array = opt_hdr + 112;  /* data directory array (PE32+) */

    /* Section table follows the optional header. One section, mapped 1:1 (RVA ==
     * file offset) and placed at 0x200 so all section contents fit inside the flat
     * 0x800-byte buffer — the section table itself ends at ~0x1B0, below 0x200. */
    const uint32_t sec = opt_hdr + opt_size;
    const uint32_t sec_va = 0x200;
    const uint32_t sec_raw = 0x200;   /* PointerToRawData == VirtualAddress (1:1) */
    put32(b, sec + 8, 0x400);         /* VirtualSize */
    put32(b, sec + 12, sec_va);       /* VirtualAddress */
    put32(b, sec + 16, 0x400);        /* SizeOfRawData */
    put32(b, sec + 20, sec_raw);      /* PointerToRawData */

    /* Export directory inside the section. */
    const uint32_t exp_rva = sec_va + 0x00;     /* IMAGE_EXPORT_DIRECTORY */
    const uint32_t funcs_rva = sec_va + 0x40;
    const uint32_t names_rva = sec_va + 0x50;
    const uint32_t ords_rva  = sec_va + 0x60;
    const uint32_t name_str_rva = sec_va + 0x70;
    const uint32_t func_code_rva = sec_va + 0x100; /* the exported prologue */

    put32(b, exp_rva + 24, 1);          /* NumberOfNames */
    put32(b, exp_rva + 28, funcs_rva);  /* AddressOfFunctions */
    put32(b, exp_rva + 32, names_rva);  /* AddressOfNames */
    put32(b, exp_rva + 36, ords_rva);   /* AddressOfNameOrdinals */

    put32(b, funcs_rva, func_code_rva); /* function[0] RVA */
    put32(b, names_rva, name_str_rva);  /* name[0] RVA */
    put16(b, ords_rva, 0);              /* ordinal[0] = 0 */
    std::memcpy(b.data() + name_str_rva, "Present", 8); /* incl NUL */

    pe.export_rva = func_code_rva;

    /* Put an absolute 64-bit pointer at the start of the prologue and a DIR64
     * relocation that targets it. On disk it holds preferred_base + 0x1234. */
    pe.reloc_target_rva = func_code_rva;
    pe.original_pointer = pe.preferred_base + 0x1234;
    put64(b, func_code_rva, pe.original_pointer);

    /* Base relocation block: page_rva = func_code_rva & ~0xFFF, one DIR64 entry. */
    const uint32_t reloc_rva = sec_va + 0x200;
    const uint32_t page_rva = func_code_rva & ~0xFFFu;
    const uint16_t entry_off = static_cast<uint16_t>(func_code_rva - page_rva);
    put32(b, reloc_rva + 0, page_rva);
    put32(b, reloc_rva + 4, 8 + 2);                  /* block size: header + 1 entry */
    put16(b, reloc_rva + 8, static_cast<uint16_t>((10u << 12) | entry_off)); /* DIR64 */

    /* Data directories: export[0], base-reloc[5]. */
    put32(b, dir_array + 0 * 8, exp_rva);
    put32(b, dir_array + 0 * 8 + 4, 0x40);
    put32(b, dir_array + 5 * 8, reloc_rva);
    put32(b, dir_array + 5 * 8 + 4, 8 + 2);

    return pe;
}

} // namespace

TEST(PeRelocate, ResolvesExportRva) {
    SynthPe pe = build_synth_pe();
    hk::sdk::pe::ImageView img(pe.bytes.data(), pe.bytes.size());
    hk::sdk::pe::PeHeaders h{};
    ASSERT_TRUE(hk::sdk::pe::parse_headers(img, h));
    EXPECT_TRUE(h.is64);
    EXPECT_EQ(h.preferred_base, pe.preferred_base);

    uint32_t rva = 0;
    ASSERT_TRUE(hk::sdk::pe::resolve_export_rva(img, h, "Present", rva));
    EXPECT_EQ(rva, pe.export_rva);

    uint32_t missing = 0;
    EXPECT_FALSE(hk::sdk::pe::resolve_export_rva(img, h, "NotThere", missing));
}

TEST(PeRelocate, RelocatedAbsolutePointerMatchesLiveBaseNotAPatch) {
    SynthPe pe = build_synth_pe();
    hk::sdk::pe::ImageView img(pe.bytes.data(), pe.bytes.size());
    hk::sdk::pe::PeHeaders h{};
    ASSERT_TRUE(hk::sdk::pe::parse_headers(img, h));

    /* Copy the on-disk prologue window (the 8-byte absolute pointer). */
    uint32_t file_off = 0;
    ASSERT_TRUE(hk::sdk::pe::rva_to_file_offset(img, h, pe.export_rva, file_off));
    uint8_t window[8];
    std::memcpy(window, pe.bytes.data() + file_off, sizeof(window));

    /* Loader maps the image at a relocated base. relocate_window must rewrite the
     * absolute pointer to live_base + 0x1234 — i.e. the value the LIVE prologue
     * holds — so a byte compare against the live image agrees (no false patch). */
    const uint64_t live_base = 0x7FF000000000ull;
    ASSERT_TRUE(hk::sdk::pe::relocate_window(img, h, live_base, pe.export_rva,
                                             window, sizeof(window)));
    uint64_t relocated = 0;
    std::memcpy(&relocated, window, sizeof(relocated));
    const int64_t delta =
        static_cast<int64_t>(live_base) - static_cast<int64_t>(pe.preferred_base);
    EXPECT_EQ(relocated, static_cast<uint64_t>(static_cast<int64_t>(pe.original_pointer) + delta));
}

TEST(PeRelocate, NoRelocationWhenLoadedAtPreferredBase) {
    SynthPe pe = build_synth_pe();
    hk::sdk::pe::ImageView img(pe.bytes.data(), pe.bytes.size());
    hk::sdk::pe::PeHeaders h{};
    ASSERT_TRUE(hk::sdk::pe::parse_headers(img, h));

    uint32_t file_off = 0;
    ASSERT_TRUE(hk::sdk::pe::rva_to_file_offset(img, h, pe.export_rva, file_off));
    uint8_t window[8];
    std::memcpy(window, pe.bytes.data() + file_off, sizeof(window));

    /* delta == 0: on-disk bytes already match the live image; window is untouched. */
    ASSERT_TRUE(hk::sdk::pe::relocate_window(img, h, pe.preferred_base, pe.export_rva,
                                             window, sizeof(window)));
    uint64_t v = 0;
    std::memcpy(&v, window, sizeof(v));
    EXPECT_EQ(v, pe.original_pointer);
}

TEST(PeRelocate, RejectsTruncatedImage) {
    SynthPe pe = build_synth_pe();
    /* Truncate to before the NT header; parse must fail cleanly, not read OOB. */
    hk::sdk::pe::ImageView img(pe.bytes.data(), 0x10);
    hk::sdk::pe::PeHeaders h{};
    EXPECT_FALSE(hk::sdk::pe::parse_headers(img, h));
}
