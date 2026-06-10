/*
 * ac/src/selfcheck/self_logic.cpp
 * Role: Pure, platform-free decision cores for the client self-integrity sensors
 *       (memory-integrity-selfcheck, catalog signals 145-153). These take already-
 *       sampled inputs (the three cross-view hashes, resolved IAT/GOT slots, DR
 *       reads, VEH ordering, TLS/init tables) and return the raw classification the
 *       sensor ships as evidence. NO platform API, NO I/O — so they are unit-tested
 *       host-side (tests/unit/test_selfcheck_logic.cpp), which is the plan's "factor
 *       the divergence/attribution logic out of the sensor TUs into pure functions"
 *       requirement (guardrail #14). None of these decides a ban: the client emits,
 *       the server decides.
 * Target platforms: all (compiled into hk_ac and the host unit-test target).
 * Interface: implements the pure cores declared in ac/include/horkos/selfcheck.h.
 */

#include "horkos/selfcheck.h"

#include <cstring>

namespace hk {
namespace selfcheck {

namespace {
/* Constant-time-irrelevant 32-byte equality (these are integrity hashes of our
 * OWN binary, not secrets — no timing channel to protect). */
bool hash_eq(const uint8_t* a, const uint8_t* b) noexcept {
    return std::memcmp(a, b, 32) == 0;
}
} // namespace

uint32_t crossview_match_matrix(const uint8_t* hash_inproc,
                                const uint8_t* hash_kernel,
                                const uint8_t* hash_disk) noexcept {
    uint32_t m = 0u;
    /* A null view is "unavailable" — leave its bits clear. An unavailable kernel
     * read must NEVER set a match bit it cannot vouch for. */
    if (hash_inproc && hash_kernel && hash_eq(hash_inproc, hash_kernel)) {
        m |= HK_SELF_MATCH_INPROC_KERNEL;
    }
    if (hash_kernel && hash_disk && hash_eq(hash_kernel, hash_disk)) {
        m |= HK_SELF_MATCH_KERNEL_DISK;
    }
    if (hash_inproc && hash_disk && hash_eq(hash_inproc, hash_disk)) {
        m |= HK_SELF_MATCH_INPROC_DISK;
    }
    return m;
}

CrossViewClass crossview_classify(uint32_t m) noexcept {
    const bool ik = (m & HK_SELF_MATCH_INPROC_KERNEL) != 0;
    const bool kd = (m & HK_SELF_MATCH_KERNEL_DISK) != 0;
    const bool id = (m & HK_SELF_MATCH_INPROC_DISK) != 0;

    if (ik && kd && id) {
        return CrossViewClass::AllAgree;
    }
    /* Inline patch / self-read-restoring hook: the spoofable in-process view
     * disagrees while the two trustworthy views (kernel foreign read, disk) agree. */
    if (kd && !ik && !id) {
        return CrossViewClass::InlinePatch;
    }
    /* The kernel sees a different page than both our in-process view and disk —
     * e.g. a CoW/redirect the in-process read happens to read-around. */
    if (id && !ik && !kd) {
        return CrossViewClass::KernelDiverge;
    }
    return CrossViewClass::Inconsistent;
}

bool page_cow_has_evidence(uint32_t private_pages, uint32_t dirty_pages) noexcept {
    /* Any code page that went private/CoW or soft-dirty is reportable raw
     * evidence. The shim/hotpatch allow-list is server-side. */
    return (private_pages != 0u) || (dirty_pages != 0u);
}

uint16_t retaddr_first_unsigned_frame(const uint8_t* frame_is_signed,
                                      uint16_t frame_count) noexcept {
    if (!frame_is_signed || frame_count == 0u) {
        return HK_SELF_FRAME_NONE;
    }
    if (frame_count > HK_SELF_MAX_FRAMES) {
        frame_count = static_cast<uint16_t>(HK_SELF_MAX_FRAMES);
    }
    /* Immediate-caller rule (the narrow, low-FP surface): only frame index 1 (the
     * caller of the guarded prologue; index 0 is the guard itself) is load-bearing.
     * A deep unsigned JIT frame further down the stack is NOT flagged here — the
     * server requires the unsigned frame to be the immediate caller AND a
     * concurrent 145/149/150 signature failure. We still report the first unsigned
     * frame index so the server can apply that rule; we do not pre-judge depth. */
    for (uint16_t i = 0; i < frame_count; ++i) {
        if (frame_is_signed[i] == 0u) {
            return i;
        }
    }
    return HK_SELF_FRAME_NONE;
}

uint32_t hwbp_in_text_mask(const uint64_t dr[4], uint32_t dr7,
                           uint64_t text_base, uint64_t text_size) noexcept {
    uint32_t mask = 0u;
    if (text_size == 0u) {
        return 0u;
    }
    const uint64_t text_end = text_base + text_size;
    for (uint32_t i = 0; i < 4u; ++i) {
        /* DR7 local/global enable bits for DRi are at bit positions (2*i) and
         * (2*i+1). A breakpoint is active iff either is set. */
        const uint32_t enable_bits = 0x3u << (2u * i);
        if ((dr7 & enable_bits) == 0u) {
            continue;
        }
        const uint64_t addr = dr[i];
        if (addr >= text_base && addr < text_end) {
            mask |= (1u << i);
        }
    }
    return mask;
}

uint32_t iat_target_flags(uint64_t slot_target_va,
                          uint64_t expected_va,
                          uint64_t expected_module_base,
                          uint64_t expected_module_size,
                          bool target_in_image,
                          bool owning_module_signed,
                          bool is_forwarder) noexcept {
    uint32_t flags = 0u;

    if (is_forwarder) {
        /* A documented export forwarder is benign — record it so the server can
         * suppress, but do not raise the displaced/wrong-module bits on it. */
        return HK_SELF_TGT_FORWARDER;
    }

    if (!target_in_image) {
        flags |= HK_SELF_TGT_PRIVATE;
    }
    if (!owning_module_signed) {
        flags |= HK_SELF_TGT_UNSIGNED;
    }

    const uint64_t mod_end = expected_module_base + expected_module_size;
    const bool in_expected_module =
        expected_module_size != 0u &&
        slot_target_va >= expected_module_base && slot_target_va < mod_end;

    if (!in_expected_module && target_in_image) {
        flags |= HK_SELF_TGT_WRONG_MODULE;
    } else if (in_expected_module && slot_target_va != expected_va) {
        /* Right module, wrong offset: a displaced/trampolined export. */
        flags |= HK_SELF_TGT_DISPLACED;
    }
    return flags;
}

bool veh_handler_ordered_ahead(uint32_t our_handler_index,
                               bool foreign_handler_ahead) noexcept {
    /* We register our VEH FIRST (the hook-free approach), so on a clean machine we
     * are index 0 and nothing precedes us. A non-zero index or a foreign handler
     * ordered ahead of ours is the signal. */
    return our_handler_index != 0u || foreign_handler_ahead;
}

TlsTamperResult tls_table_tampered(uint32_t live_count, uint32_t disk_count,
                                   const uint64_t* live_rebased,
                                   const uint64_t* expected_rebased,
                                   uint32_t compare_count,
                                   const uint8_t* live_pc_in_text) noexcept {
    if (live_count != disk_count) {
        return TlsTamperResult::Tampered; /* a callback was appended/removed */
    }
    if (!live_rebased || !expected_rebased) {
        return TlsTamperResult::Unavailable; /* nothing to compare; absence of data is not evidence */
    }
    for (uint32_t i = 0; i < compare_count; ++i) {
        if (live_rebased[i] != expected_rebased[i]) {
            return TlsTamperResult::Tampered; /* a callback pointer was rebased to a foreign target */
        }
        if (live_pc_in_text && live_pc_in_text[i] == 0u) {
            return TlsTamperResult::Tampered; /* a live callback PC resolves outside our text */
        }
    }
    return TlsTamperResult::Clean;
}

} // namespace selfcheck
} // namespace hk
