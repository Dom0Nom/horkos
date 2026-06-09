/*
 * daemon/macos/HKMmapBaseline.cpp
 * Role: Per-title signed-dylib + sanctioned-JIT manifest used to gate MMAP-exec
 *       reports (signal 111). Classifies an executable mmap source as KNOWN
 *       (signed dylib in the manifest), UNKNOWN (unrecognised exec source), or
 *       ANON_RWX (anonymous executable map). Pure lookup so it is host-runnable
 *       and kept OFF the ES serial queue.
 * Target platform: macOS only (built behind `if(APPLE)`).
 * Interface: implements HKMmapBaselineMatch() from HKMmapBaseline.h.
 *
 * Guardrail compliance:
 *   #1  No platform #ifdef — CMake selects this TU.
 *   #7-adjacent  This is the daemon-side FP gate; the catalog (and the plan)
 *       require the gate to live HERE / server-side, never inline on the ES
 *       queue. The ES handler emits the digest; this classifies it later.
 */

#include "HKMmapBaseline.h"
#include "horkos/event_schema_macos.h"  /* HK_MMAP_BASELINE_* */

#include <string.h>

extern "C" uint32_t HKMmapBaselineMatch(const uint8_t        *source_path_sha256,
                                        bool                  is_anon,
                                        const HKMmapManifest *manifest) {
    /* An anonymous executable map has no backing file to match against the
     * signed-dylib manifest. If the title is JIT-entitled it is sanctioned
     * (classified KNOWN so the server does not flag legitimate JIT); otherwise
     * it is the high-signal ANON_RWX case. */
    if (is_anon || source_path_sha256 == nullptr) {
        if (manifest != nullptr && manifest->jit_entitled) {
            return HK_MMAP_BASELINE_KNOWN;
        }
        return HK_MMAP_BASELINE_ANON_RWX;
    }

    if (manifest != nullptr && manifest->entries != nullptr) {
        for (size_t i = 0; i < manifest->count; ++i) {
            /* Constant-work compare per entry; digests are 32 bytes. memcmp is
             * fine here (no secret-dependent timing concern — these are public
             * file digests, not keys). */
            if (memcmp(manifest->entries[i].source_path_sha256,
                       source_path_sha256, 32) == 0) {
                return HK_MMAP_BASELINE_KNOWN;
            }
        }
    }

    /* HK-TODO(schema/loader): the signed per-title manifest LOADER (verify the
     * manifest signature, populate HKMmapManifest from disk) is a later-phase
     * concern. This phase ships the classifier; the daemon passes an empty
     * manifest until the loader lands, so every non-anon source classifies
     * UNKNOWN and the server treats it as low-confidence pending the baseline. */
    return HK_MMAP_BASELINE_UNKNOWN;
}
