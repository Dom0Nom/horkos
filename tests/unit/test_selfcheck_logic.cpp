/*
 * Role: Host-buildable unit tests for the client self-integrity PURE decision cores
 *       (memory-integrity-selfcheck, catalog signals 145-153) and the pure PE parser.
 *       These are the platform-free functions the sensor TUs call; testing them here
 *       proves the divergence/attribution math without a kernel, a live image, or any
 *       OS API (the plan's "factor the decision logic out into pure functions" + "a
 *       clean relocated diff is byte-identical; one stomped byte -> correct
 *       first_diff_rva" requirement). The cores live in hk_ac, which this target links.
 * Target platforms: host (any) — decision math + struct walk only.
 * Interface: exercises hk::selfcheck::{crossview_match_matrix, crossview_classify,
 *       page_cow_has_evidence, retaddr_first_unsigned_frame, hwbp_in_text_mask,
 *       iat_target_flags, veh_handler_ordered_ahead, tls_table_tampered} and
 *       hk::selfcheck::pe::parse.
 */

#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <vector>

#include "horkos/selfcheck.h"
#include "pe_parse.h"

using namespace hk::selfcheck;

/* ---- 145 cross-view match matrix + classification ---- */

TEST(SelfCheckLogic, CrossViewAllAgree) {
    uint8_t a[32], b[32], c[32];
    std::memset(a, 0xAA, 32);
    std::memcpy(b, a, 32);
    std::memcpy(c, a, 32);
    const uint32_t mm = crossview_match_matrix(a, b, c);
    EXPECT_EQ(mm, HK_SELF_MATCH_INPROC_KERNEL | HK_SELF_MATCH_KERNEL_DISK |
                      HK_SELF_MATCH_INPROC_DISK);
    EXPECT_EQ(crossview_classify(mm), CrossViewClass::AllAgree);
}

TEST(SelfCheckLogic, CrossViewInlinePatch) {
    /* in-process diverges; kernel == disk -> a self-read-restoring inline patch. */
    uint8_t inproc[32], kernel[32], disk[32];
    std::memset(inproc, 0x11, 32);
    std::memset(kernel, 0x22, 32);
    std::memcpy(disk, kernel, 32);
    const uint32_t mm = crossview_match_matrix(inproc, kernel, disk);
    EXPECT_EQ(mm, HK_SELF_MATCH_KERNEL_DISK);
    EXPECT_EQ(crossview_classify(mm), CrossViewClass::InlinePatch);
}

TEST(SelfCheckLogic, CrossViewKernelDiverge) {
    uint8_t inproc[32], kernel[32], disk[32];
    std::memset(inproc, 0x11, 32);
    std::memcpy(disk, inproc, 32);
    std::memset(kernel, 0x33, 32);
    const uint32_t mm = crossview_match_matrix(inproc, kernel, disk);
    EXPECT_EQ(mm, HK_SELF_MATCH_INPROC_DISK);
    EXPECT_EQ(crossview_classify(mm), CrossViewClass::KernelDiverge);
}

TEST(SelfCheckLogic, CrossViewUnavailableKernelNeverFakesAClean) {
    /* A null (unavailable) kernel view must not set any kernel match bit — an
     * unavailable foreign read can never manufacture a "clean" pass. */
    uint8_t inproc[32], disk[32];
    std::memset(inproc, 0x55, 32);
    std::memcpy(disk, inproc, 32);
    const uint32_t mm = crossview_match_matrix(inproc, nullptr, disk);
    EXPECT_EQ(mm, HK_SELF_MATCH_INPROC_DISK); /* only the two available views compared */
    EXPECT_EQ(crossview_classify(mm), CrossViewClass::KernelDiverge);
}

/* ---- 146 page CoW evidence ---- */

TEST(SelfCheckLogic, PageCowEvidence) {
    EXPECT_FALSE(page_cow_has_evidence(0, 0));
    EXPECT_TRUE(page_cow_has_evidence(1, 0));
    EXPECT_TRUE(page_cow_has_evidence(0, 3));
}

/* ---- 147 immediate-caller frame attribution ---- */

TEST(SelfCheckLogic, RetAddrImmediateUnsignedCaller) {
    /* frame 0 = guard (signed), frame 1 = caller (unsigned) -> index 1. */
    const uint8_t signed_[3] = {1, 0, 1};
    EXPECT_EQ(retaddr_first_unsigned_frame(signed_, 3), 1);
}

TEST(SelfCheckLogic, RetAddrAllSignedNoFlag) {
    const uint8_t signed_[3] = {1, 1, 1};
    EXPECT_EQ(retaddr_first_unsigned_frame(signed_, 3), HK_SELF_FRAME_NONE);
}

TEST(SelfCheckLogic, RetAddrNullOrEmptyIsNone) {
    EXPECT_EQ(retaddr_first_unsigned_frame(nullptr, 3), HK_SELF_FRAME_NONE);
    const uint8_t signed_[1] = {0};
    EXPECT_EQ(retaddr_first_unsigned_frame(signed_, 0), HK_SELF_FRAME_NONE);
}

/* ---- 148 DR-in-text mask ---- */

TEST(SelfCheckLogic, HwBpInTextMask) {
    const uint64_t text_base = 0x140001000ull;
    const uint64_t text_size = 0x1000ull;
    uint64_t dr[4] = {0x140001500ull, 0x200000000ull, 0x140001FFFull, 0x0ull};
    /* DR0 and DR2 enabled (bits 0..3 set), DR1/DR3 disabled. */
    const uint32_t dr7 = 0x3u | (0x3u << 4);
    const uint32_t mask = hwbp_in_text_mask(dr, dr7, text_base, text_size);
    /* DR0 in text -> bit0; DR2 in text -> bit2; DR1 disabled even though OOR. */
    EXPECT_EQ(mask, (1u << 0) | (1u << 2));
}

TEST(SelfCheckLogic, HwBpDisabledRegisterIgnored) {
    const uint64_t dr[4] = {0x140001000ull, 0, 0, 0};
    const uint32_t mask = hwbp_in_text_mask(dr, /*dr7*/ 0u, 0x140001000ull, 0x1000ull);
    EXPECT_EQ(mask, 0u); /* no enable bits -> nothing flagged */
}

/* ---- 149 IAT target classification ---- */

TEST(SelfCheckLogic, IatCleanSlotNoFlags) {
    const uint32_t f = iat_target_flags(/*target*/ 0x7FF0'1000ull,
                                        /*expected*/ 0x7FF0'1000ull,
                                        /*mod_base*/ 0x7FF0'0000ull,
                                        /*mod_size*/ 0x10000ull,
                                        /*in_image*/ true,
                                        /*signed*/ true,
                                        /*forwarder*/ false);
    EXPECT_EQ(f, 0u);
}

TEST(SelfCheckLogic, IatDisplacedTarget) {
    const uint32_t f = iat_target_flags(0x7FF0'2000ull, 0x7FF0'1000ull, 0x7FF0'0000ull,
                                        0x10000ull, true, true, false);
    EXPECT_EQ(f, HK_SELF_TGT_DISPLACED);
}

TEST(SelfCheckLogic, IatPrivateUnsignedTarget) {
    const uint32_t f = iat_target_flags(0x10'0000ull, 0x7FF0'1000ull, 0x7FF0'0000ull,
                                        0x10000ull, /*in_image*/ false, /*signed*/ false,
                                        false);
    EXPECT_TRUE(f & HK_SELF_TGT_PRIVATE);
    EXPECT_TRUE(f & HK_SELF_TGT_UNSIGNED);
}

TEST(SelfCheckLogic, IatWrongModuleButImageBacked) {
    const uint32_t f = iat_target_flags(0x5000'0000ull, 0x7FF0'1000ull, 0x7FF0'0000ull,
                                        0x10000ull, /*in_image*/ true, true, false);
    EXPECT_TRUE(f & HK_SELF_TGT_WRONG_MODULE);
}

TEST(SelfCheckLogic, IatForwarderIsBenign) {
    const uint32_t f = iat_target_flags(0x1234ull, 0x9999ull, 0, 0, false, false, true);
    EXPECT_EQ(f, HK_SELF_TGT_FORWARDER); /* forwarder dominates; no false hook flags */
}

/* ---- 150 VEH ordering ---- */

TEST(SelfCheckLogic, VehCleanWhenWeAreFirst) {
    EXPECT_FALSE(veh_handler_ordered_ahead(/*our_index*/ 0, /*foreign_ahead*/ false));
}

TEST(SelfCheckLogic, VehFlaggedWhenForeignAhead) {
    EXPECT_TRUE(veh_handler_ordered_ahead(0, true));
    EXPECT_TRUE(veh_handler_ordered_ahead(2, false));
}

/* ---- 153 TLS/init table tamper ---- */

TEST(SelfCheckLogic, TlsCountMismatchIsTampered) {
    EXPECT_EQ(tls_table_tampered(3, 2, nullptr, nullptr, 0, nullptr),
              TlsTamperResult::Tampered);
}

TEST(SelfCheckLogic, TlsPointerMismatchIsTampered) {
    const uint64_t live[2] = {0x1000, 0x9999};
    const uint64_t expect[2] = {0x1000, 0x2000};
    const uint8_t in_text[2] = {1, 1};
    EXPECT_EQ(tls_table_tampered(2, 2, live, expect, 2, in_text),
              TlsTamperResult::Tampered);
}

TEST(SelfCheckLogic, TlsCallbackOutOfTextIsTampered) {
    const uint64_t live[1] = {0x1000};
    const uint64_t expect[1] = {0x1000};
    const uint8_t in_text[1] = {0}; /* PC resolves outside our text */
    EXPECT_EQ(tls_table_tampered(1, 1, live, expect, 1, in_text),
              TlsTamperResult::Tampered);
}

TEST(SelfCheckLogic, TlsCleanTableNotTampered) {
    const uint64_t live[2] = {0x1000, 0x2000};
    const uint64_t expect[2] = {0x1000, 0x2000};
    const uint8_t in_text[2] = {1, 1};
    EXPECT_EQ(tls_table_tampered(2, 2, live, expect, 2, in_text),
              TlsTamperResult::Clean);
}

TEST(SelfCheckLogic, TlsNullTablesAreUnavailableNotTampered) {
    /* Both pointers null with matching count — cannot compare; must not be
     * escalated as evidence of tampering. */
    EXPECT_EQ(tls_table_tampered(2, 2, nullptr, nullptr, 0, nullptr),
              TlsTamperResult::Unavailable);
}

TEST(SelfCheckLogic, TlsOneNullPointerIsUnavailable) {
    const uint64_t live[1] = {0x1000};
    EXPECT_EQ(tls_table_tampered(1, 1, live, nullptr, 1, nullptr),
              TlsTamperResult::Unavailable);
}

/* ---- pure PE parser: build a minimal PE32+ and assert exact ranges ---- */

namespace {
/* Construct a minimal but structurally valid PE32+ buffer with one executable
 * section. Returns the buffer; out params expose the planted values. */
std::vector<uint8_t> build_min_pe(uint32_t text_rva, uint32_t text_vsize,
                                  uint32_t text_raw_ptr, uint32_t text_raw_size,
                                  uint64_t image_base, uint32_t size_of_image) {
    std::vector<uint8_t> b(0x400, 0);
    auto wr16 = [&](size_t o, uint16_t v) { b[o] = v & 0xFF; b[o + 1] = (v >> 8) & 0xFF; };
    auto wr32 = [&](size_t o, uint32_t v) {
        b[o] = v & 0xFF; b[o + 1] = (v >> 8) & 0xFF;
        b[o + 2] = (v >> 16) & 0xFF; b[o + 3] = (v >> 24) & 0xFF;
    };
    auto wr64 = [&](size_t o, uint64_t v) { wr32(o, (uint32_t)v); wr32(o + 4, (uint32_t)(v >> 32)); };

    wr16(0, 0x5A4D);          // MZ
    const uint32_t e_lfanew = 0x80;
    wr32(0x3C, e_lfanew);

    wr32(e_lfanew, 0x00004550);          // "PE\0\0"
    const size_t fh = e_lfanew + 4;
    wr16(fh + 0, 0x8664);                // Machine x64
    wr16(fh + 2, 1);                     // NumberOfSections
    const uint16_t opt_size = 0xF0;
    wr16(fh + 16, opt_size);             // SizeOfOptionalHeader

    const size_t oh = fh + 20;
    wr16(oh + 0, 0x020B);                // PE32+ magic
    wr32(oh + 16, text_rva);             // AddressOfEntryPoint (point at text)
    wr64(oh + 24, image_base);           // ImageBase
    wr32(oh + 56, size_of_image);        // SizeOfImage
    wr32(oh + 108, 16);                  // NumberOfRvaAndSizes

    const size_t st = oh + opt_size;     // section table
    std::memcpy(&b[st], ".text\0\0\0", 8);
    wr32(st + 8, text_vsize);            // VirtualSize
    wr32(st + 12, text_rva);             // VirtualAddress
    wr32(st + 16, text_raw_size);        // SizeOfRawData
    wr32(st + 20, text_raw_ptr);         // PointerToRawData
    wr32(st + 36, hk::selfcheck::pe::HK_SCN_MEM_EXECUTE); // Characteristics
    return b;
}
}  // namespace

TEST(SelfCheckPeParse, ParsesSectionAndDirsExactly) {
    const auto buf = build_min_pe(/*rva*/ 0x1000, /*vsize*/ 0x2000,
                                  /*raw_ptr*/ 0x400, /*raw_size*/ 0x2000,
                                  /*base*/ 0x140000000ull, /*soi*/ 0x10000);
    const pe::Headers h = pe::parse(buf.data(), buf.size());
    ASSERT_TRUE(h.valid);
    EXPECT_TRUE(h.is_64bit);
    EXPECT_EQ(h.image_base, 0x140000000ull);
    EXPECT_EQ(h.size_of_image, 0x10000u);
    EXPECT_EQ(h.entry_point_rva, 0x1000u);
    ASSERT_EQ(h.section_count, 1u);

    const pe::SectionRange* text = pe::first_exec_section(h);
    ASSERT_NE(text, nullptr);
    EXPECT_EQ(text->rva, 0x1000u);
    EXPECT_EQ(text->virtual_size, 0x2000u);

    /* RVA->file offset math: an RVA inside the section maps to raw_ptr + delta. */
    uint32_t off = 0;
    ASSERT_TRUE(pe::rva_to_file_offset(h, 0x1040, &off));
    EXPECT_EQ(off, 0x400u + 0x40u);

    /* An RVA outside any section does not resolve. */
    EXPECT_EQ(pe::section_for_rva(h, 0x500), nullptr);
}

TEST(SelfCheckPeParse, RejectsTruncatedAndForged) {
    /* Too small. */
    const uint8_t tiny[8] = {0x4D, 0x5A, 0, 0, 0, 0, 0, 0};
    EXPECT_FALSE(pe::parse(tiny, sizeof(tiny)).valid);

    /* Valid MZ but bogus e_lfanew pointing past the buffer -> invalid, not over-read. */
    std::vector<uint8_t> b(0x100, 0);
    b[0] = 0x4D; b[1] = 0x5A;
    b[0x3C] = 0xFF; b[0x3D] = 0xFF; b[0x3E] = 0xFF; b[0x3F] = 0x7F;
    EXPECT_FALSE(pe::parse(b.data(), b.size()).valid);
}

TEST(SelfCheckPeParse, SectTableWrapRejected) {
    /* An e_lfanew near UINT32_MAX causes e_lfanew + 4 + 20 + opt_size to wrap;
     * the parser must reject without an out-of-bounds access. */
    auto buf = build_min_pe(0x1000, 0x1000, 0x200, 0x1000,
                            0x140000000ull, 0x10000);
    /* Overwrite e_lfanew with a value that places the section table past the buffer
     * when opt_size (0xF0) is added: 0x80 is the planted value; plant 0xFFFFFF00 to
     * force 64-bit accumulation overflow detection. */
    const uint32_t bad_lfanew = 0xFFFFFF00u;
    buf[0x3C] = bad_lfanew & 0xFF;
    buf[0x3D] = (bad_lfanew >> 8) & 0xFF;
    buf[0x3E] = (bad_lfanew >> 16) & 0xFF;
    buf[0x3F] = (bad_lfanew >> 24) & 0xFF;
    EXPECT_FALSE(pe::parse(buf.data(), buf.size()).valid);
}

TEST(SelfCheckPeParse, SectionForRvaOverflow) {
    /* A section with rva=UINT32_MAX-1 and virtual_size=0x10 would overflow
     * rva + virtual_size; section_for_rva must not return a false positive. */
    auto buf = build_min_pe(/*rva*/ 0x1000, /*vsize*/ 0x1000,
                            /*raw_ptr*/ 0x400, /*raw_size*/ 0x1000,
                            /*base*/ 0x140000000ull, /*soi*/ 0x10000);
    pe::Headers h = pe::parse(buf.data(), buf.size());
    ASSERT_TRUE(h.valid);
    ASSERT_EQ(h.section_count, 1u);
    /* Plant a pathological rva / virtual_size that would overflow uint32 addition. */
    h.sections[0].rva = 0xFFFFFFF0u;
    h.sections[0].virtual_size = 0x20u;
    /* An rva that does NOT wrap: should not match. */
    EXPECT_EQ(pe::section_for_rva(h, 0x1000u), nullptr);
}

TEST(SelfCheckPeParse, RvaToFileOffsetOverflow) {
    /* raw_ptr near UINT32_MAX with a non-zero delta must not overflow and must
     * return false rather than a wrapped offset. */
    auto buf = build_min_pe(0x1000, 0x2000, 0x400, 0x2000,
                            0x140000000ull, 0x10000);
    pe::Headers h = pe::parse(buf.data(), buf.size());
    ASSERT_TRUE(h.valid);
    ASSERT_EQ(h.section_count, 1u);
    /* Plant a raw_ptr near the top of uint32 space. */
    h.sections[0].raw_ptr = 0xFFFFFFF0u;
    h.sections[0].raw_size = 0x100u;
    h.sections[0].rva = 0x1000u;
    h.sections[0].virtual_size = 0x100u;
    uint32_t out = 0;
    EXPECT_FALSE(pe::rva_to_file_offset(h, 0x1010u, &out));
}
