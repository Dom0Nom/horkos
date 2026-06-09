/*
 * daemon/macos/HKThreadIntegrity.h
 * Role: Interface for thread-origin scanning (signal 114). Declares HKThreadScan()
 *       and the pure image-region resolver that classifies an entry PC as inside
 *       a known mach-o image vs anonymous vs a sanctioned JIT region.
 * Target platform: macOS only (CMake `if(APPLE)` gates the implementing TU).
 * Interface: daemon-only. The resolver is pure and host-runnable for unit tests.
 */

#pragma once

#include "HKGameTaskHandle.h"
#include "horkos/event_schema_macos.h"  /* hk_es_thread_origin, HK_REGION_* */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* One mapped image region in the game's address space: [base, base+size). The
 * caller builds this list from the game's dyld image set (or, in tests, supplies
 * a synthetic list). */
typedef struct HKImageRegion {
    uint64_t base;
    uint64_t size;
} HKImageRegion;

/* One sanctioned JIT region: [base, base+size). Derived from the signal-111 mmap
 * baseline (a JIT-entitled title's sanctioned executable maps). */
typedef struct HKJitRegion {
    uint64_t base;
    uint64_t size;
} HKJitRegion;

/*
 * HKResolveEntryRegion — classify `entry_pc` (PURE; host-runnable).
 *
 *   images / image_count : known mach-o image regions.
 *   jit / jit_count      : sanctioned JIT regions (may be 0).
 *
 * Returns HK_REGION_IMAGE if entry_pc falls in any image region;
 *         HK_REGION_JIT_SANCTIONED if it falls in a sanctioned JIT region;
 *         HK_REGION_ANON otherwise (foreign/unbacked entry — high-signal).
 * Image membership takes precedence over JIT (a PC inside a real image is not a
 * JIT thread regardless of overlap).
 */
uint32_t HKResolveEntryRegion(uint64_t             entry_pc,
                              const HKImageRegion *images, size_t image_count,
                              const HKJitRegion   *jit,    size_t jit_count);

/*
 * HKThreadScan — enumerate the game's threads, resolve each entry PC, and emit a
 * hk_es_thread_origin for any non-IMAGE entry via `emit`. No-op on an invalid
 * game-task handle. Returns the number of events emitted (0 on no-op).
 */
typedef void (*HKThreadOriginEmit)(const hk_es_thread_origin *event, void *ctx);

size_t HKThreadScan(const HKGameTaskHandle *game,
                    const HKImageRegion    *images, size_t image_count,
                    const HKJitRegion      *jit,    size_t jit_count,
                    HKThreadOriginEmit      emit,   void  *ctx);

#ifdef __cplusplus
}  /* extern "C" */
#endif
