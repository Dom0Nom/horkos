/*
 * Role: Pure, platform-free section-diff core for signal 12 (on-disk vs
 *       in-memory code mismatch = "module stomp"). The FP-prone heart of the
 *       signal: a loaded module's code legitimately differs from its on-disk
 *       backing at relocation sites (the loader rewrites them for the load base)
 *       and at IAT thunks (the loader binds imports). This core EXCLUDES those
 *       expected-difference bytes, then reports the first remaining mismatch RVA
 *       (or "clean") — so a benign relocated+bound module diffs clean while a
 *       single stomped code byte is caught. Pure byte math, no kernel/Win32 API,
 *       unit-tested host-side (tests/unit/test_mem_stomp_logic.cpp) without a WDK.
 *       The kernel sampler (ModuleStomp.c) maps the on-disk backing read-only and
 *       reads the live mapping read-only; it ships the RAW first-diff RVA + both
 *       section hashes — NEVER a verdict (FP risk is high: hotpatch, Detours,
 *       overlays). The server classifies.
 *       READ-ONLY: compares two buffers; mutates neither input.
 * Target platforms: all (diff math; the mapping/reading is Win-kernel-only).
 * Interface: consumed by kernel/win/src/ModuleStomp.c.
 */

#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* A span of bytes the loader legitimately rewrites: one relocation fix-up site
 * (width = the pointer width the relocation patched, e.g. 8 on x64) or one IAT
 * thunk range. Both are excluded from the stomp comparison. */
typedef struct hk_byte_span {
    uint32_t rva;  /* offset within the compared section buffer. */
    uint32_t len;  /* number of bytes the loader may have changed. */
} hk_byte_span;

/* True if byte offset `off` falls inside any excluded span. Bounded scan over a
 * caller-supplied, capped span list. A NULL list excludes nothing. */
static inline int hk_mem_offset_excluded(uint32_t off,
                                         const hk_byte_span *spans, uint32_t count)
{
    uint32_t i;
    if (spans == 0) {
        return 0;
    }
    for (i = 0; i < count; ++i) {
        uint32_t start = spans[i].rva;
        uint32_t end;
        /* Guard against overflow on a malformed span: clamp rather than wrap. */
        if (spans[i].len == 0u) {
            continue;
        }
        if (start > 0xFFFFFFFFu - spans[i].len) {
            end = 0xFFFFFFFFu;
        } else {
            end = start + spans[i].len;
        }
        if (off >= start && off < end) {
            return 1;
        }
    }
    return 0;
}

/*
 * Compare the on-disk section bytes against the live mapped bytes, excluding the
 * relocation and IAT spans. Returns the RVA (offset within the buffer) of the
 * first unexplained mismatch, or -1 if the section is clean once normalized.
 *
 * `reloc_sites` are the relocation fix-up spans; `iat_ranges` are the IAT thunk
 * spans. Both lists are caller-built and capped. A NULL/empty buffer or zero
 * length returns -1 (defined "no signal" — never UB): the caller (ModuleStomp.c)
 * cannot diff what it could not map.
 *
 * The caller adds the section's base RVA to the result before it crosses the
 * wire so the server sees a module-relative RVA.
 */
static inline int32_t hk_mem_first_diff_rva(const uint8_t *disk,
                                            const uint8_t *live, uint32_t len,
                                            const hk_byte_span *reloc_sites,
                                            uint32_t reloc_count,
                                            const hk_byte_span *iat_ranges,
                                            uint32_t iat_count)
{
    uint32_t i;
    if (disk == 0 || live == 0 || len == 0u) {
        return -1;
    }
    for (i = 0; i < len; ++i) {
        if (disk[i] == live[i]) {
            continue;
        }
        if (hk_mem_offset_excluded(i, reloc_sites, reloc_count)) {
            continue;
        }
        if (hk_mem_offset_excluded(i, iat_ranges, iat_count)) {
            continue;
        }
        return (int32_t)i;
    }
    return -1;
}

#ifdef __cplusplus
} /* extern "C" */
#endif
