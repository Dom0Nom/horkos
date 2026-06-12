/*
 * Role: Pure, platform-free classifiers for the loader/image memory signals 13
 *       (image region absent from the PEB loader lists = "ghost"), 16
 *       (hollow/doppelgang backing: name/state mismatch), and 17 (thread Win32
 *       start address / TLS callback resolving into an unbacked region). Each is
 *       a structural decision over already-normalized inputs (resolved bases,
 *       backing-state flags, resolved VadType), no kernel/Win32 API — so the
 *       logic is unit-tested host-side (tests/unit/test_mem_image_logic.cpp)
 *       without a WDK. The kernel samplers (LdrCrosscheck.c / HollowDetect.c /
 *       ExecOrigin.c) feed these the sampled state and emit the raw match; NONE
 *       decide a ban — the client emits, the server fuses.
 *       READ-ONLY: classifies observed state; mutates nothing.
 * Target platforms: all (decision math; the sampling is Win-kernel-only).
 * Interface: consumed by LdrCrosscheck.c / HollowDetect.c / ExecOrigin.c.
 */

#pragma once

#include <stdint.h>

#include "mem_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Is `image_base` present in a loader-list base array? Bounded linear scan; a
 * NULL/empty list contributes no match. The image base is the strong identity
 * key — the kernel resolves each PEB.Ldr entry to its DllBase before calling.
 */
static inline int hk_mem_base_in_list(uint64_t image_base,
                                      const uint64_t *bases, uint32_t count)
{
    uint32_t i;
    if (bases == 0) {
        return 0;
    }
    for (i = 0; i < count; ++i) {
        if (bases[i] == image_base) {
            return 1;
        }
    }
    return 0;
}

/*
 * Signal 13 — ghost image: an image-backed executable VAD whose base appears in
 * NONE of the three PEB.Ldr lists (InLoadOrder / InMemoryOrder /
 * InInitializationOrder). A normally-loaded module is in all three; a
 * manually-mapped image that bypassed LdrLoadDll is in none. Raw structural
 * match only. The caller must already have skipped exiting processes (loader
 * teardown transiently removes entries) and confirmed the region is image +X.
 */
static inline int hk_mem_is_ghost(uint64_t image_base,
                                  const uint64_t *load_order, uint32_t load_count,
                                  const uint64_t *mem_order, uint32_t mem_count,
                                  const uint64_t *init_order, uint32_t init_count)
{
    if (hk_mem_base_in_list(image_base, load_order, load_count)) {
        return 0;
    }
    if (hk_mem_base_in_list(image_base, mem_order, mem_count)) {
        return 0;
    }
    if (hk_mem_base_in_list(image_base, init_order, init_count)) {
        return 0;
    }
    return 1;
}

/*
 * Signal 16 — hollow/doppelgang backing. The combined gate the catalog mandates:
 * the region is executable AND contains the entry point AND shows at least one
 * backing anomaly (FILE_OBJECT name != Ldr path, delete-pending, or transacted).
 * Any one anomaly alone is benign (legit transacted installers, name quirks); the
 * combination with an executable entry-point region is the hollowing shape.
 */
static inline int hk_mem_is_hollow(int exec, int entry_region,
                                   int delete_pending, int transacted,
                                   int name_mismatch)
{
    int anomaly = (delete_pending || transacted || name_mismatch) ? 1 : 0;
    return (exec && entry_region && anomaly) ? 1 : 0;
}

/* Build the hk_event_mem_image_anomaly.flags mask for signal 16 from the sampled
 * backing state. Pure mapping; the sampler copies it into the emitted record. */
static inline uint32_t hk_mem_hollow_flags(int exec, int entry_region,
                                           int delete_pending, int transacted,
                                           int name_mismatch, int has_jit_owner)
{
    uint32_t flags = HK_MEM_IMG_FLAG_HOLLOW;
    if (exec) {
        flags |= HK_MEM_IMG_FLAG_EXEC;
    }
    if (entry_region) {
        flags |= HK_MEM_IMG_FLAG_ENTRY_REGION;
    }
    if (delete_pending) {
        flags |= HK_MEM_IMG_FLAG_DELETE_PENDING;
    }
    if (transacted) {
        flags |= HK_MEM_IMG_FLAG_TRANSACTED;
    }
    if (name_mismatch) {
        flags |= HK_MEM_IMG_FLAG_NAME_MISMATCH;
    }
    if (has_jit_owner) {
        flags |= HK_MEM_IMG_FLAG_HAS_JIT_OWNER;
    }
    return flags;
}

/*
 * Signal 17 — execution origin anon: a thread's Win32 start address (or a
 * module's TLS callback target) resolves into a region with no image backing
 * (normalized VadType NONE = private/anon). A JIT owner suppresses it (JITs
 * legitimately start threads in generated code). Raw structural match only.
 */
static inline int hk_mem_origin_is_anon(uint32_t resolved_vad_type,
                                        int has_jit_owner)
{
    if (has_jit_owner) {
        return 0;
    }
    return (resolved_vad_type == HK_MEM_VAD_NONE) ? 1 : 0;
}

#ifdef __cplusplus
} /* extern "C" */
#endif
