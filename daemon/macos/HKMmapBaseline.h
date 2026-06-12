/*
 * Role: Interface for the per-title mmap-exec baseline. Declares the manifest
 *       struct and HKMmapBaselineMatch(), consulted by the ES MMAP handler (via
 *       the daemon) to classify an executable mmap source as KNOWN / UNKNOWN /
 *       ANON_RWX (signal 111). Keeps the FP gate off the ES serial queue.
 * Target platform: macOS only (CMake `if(APPLE)` gates the TU).
 * Interface: declared for daemon TUs only.
 */

#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* One sanctioned exec-map source: a SHA-256 of a signed dylib path the title is
 * expected to map executable. The manifest is per-title and signed; loading it
 * is the daemon's job (the loader is a later-phase concern — see HK-TODO below). */
typedef struct HKMmapManifestEntry {
    uint8_t source_path_sha256[32];
} HKMmapManifestEntry;

typedef struct HKMmapManifest {
    const HKMmapManifestEntry *entries;  /* sanctioned signed-dylib digests */
    size_t                     count;
    bool                       jit_entitled;  /* title holds cs.allow-jit */
} HKMmapManifest;

/*
 * HKMmapBaselineMatch — classify an executable mmap.
 *
 *   source_path_sha256 : digest of the es_event_mmap_t.source path (NULL for an
 *                        anonymous map).
 *   is_anon            : true if the map is MAP_ANON (no backing file).
 *   manifest           : the per-title baseline (may be empty on a fresh title).
 *
 * Returns one of HK_MMAP_BASELINE_KNOWN / _UNKNOWN / _ANON_RWX
 * (event_schema_macos.h). Pure lookup — no syscalls, host-runnable in unit tests.
 */
uint32_t HKMmapBaselineMatch(const uint8_t       *source_path_sha256,
                             bool                 is_anon,
                             const HKMmapManifest *manifest);

#ifdef __cplusplus
}  /* extern "C" */
#endif
