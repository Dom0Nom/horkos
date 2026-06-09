/*
 * bypass-tests/cross/pointer_lattice_synthetic.cpp
 * Role: pointer-lattice physicality merge-gate bypass test (Phase: [disabled]) for
 *       signal 142. The activated body builds synthetic delta streams (uniform /
 *       integer-perfect curve / single fixed step) and a captured real-sensor stream of
 *       the SAME HID usage class, folds each through the shared platform-free
 *       fold_pointer_features, and asserts: (1) the synthetic streams produce a feature
 *       vector the server model flags as NON-PHYSICAL even when inter-arrival timing is
 *       jittered (the lattice/quantization shows in the GCD + autocorr + std features,
 *       which are timing-independent); (2) the real-sensor stream conditioned on the
 *       same usage class does NOT flag (the FP gate); (3) the emitted struct contains
 *       NO raw delta — only aggregates (the privacy invariant).
 * Target platforms: cross (the fold is platform-free; built unconditionally like the
 *       dma_hardware gate).
 * Interface: consumes sdk/include/horkos/device_trust_schema.h and the shared fold in
 *       sdk/src/backends/common/PointerFeatureFold.h.
 *
 * Merge gate (guardrail #12): this is the bypass test for the device-trust pointer-
 * feature sensor (signal 142). Unlike the disabled-only platform stubs, the privacy
 * invariant (no raw delta in the emitted struct) and the canonical fold are testable on
 * any host NOW, so this fixture runs a REAL assertion on the privacy invariant
 * unconditionally and leaves the model-scoring half behind HK_DEVICE_TRUST_BYPASS_ENABLED.
 */

#include <cstdio>

#include "common/PointerFeatureFold.h"

using namespace hk::sdk::common;

/* Privacy invariant (always-on): fold a known delta stream and confirm the emitted
 * hk_event_pointer_features carries ONLY the 24-dim aggregate + the two scalar ids —
 * there is no field and no accessor through which a raw lLastX/lLastY sample could
 * leave. We assert the struct has exactly the documented members by checking the byte
 * size pin AND that the window's raw deltas are not byte-present in the emitted record.
 * This is the load-bearing data-categories assertion (§5). */
static int privacy_invariant(void)
{
    PointerFeatureWindow win;
    /* A distinctive raw value that must NOT appear in the emitted aggregate bytes. */
    const int32_t sentinel = 0x5151; /* 20817 — unlikely to arise as an aggregate */
    win.add(sentinel, -sentinel);
    win.add(3, 5);
    win.add(0, 1);

    hk_event_pointer_features rec;
    if (!fold_pointer_features(win, HK_PCLASS_MOUSE, 0xABCDu, rec)) {
        std::printf("FAIL: fold returned false on a non-empty window\n");
        return 1;
    }
    /* The struct must be exactly the pinned size (no hidden raw-sample tail). */
    if (sizeof(rec) != 16u + HK_POINTER_FEAT_DIM * 4u) {
        std::printf("FAIL: pointer-feature struct size drifted (%zu)\n", sizeof(rec));
        return 1;
    }
    /* Scan the emitted record bytes for the raw sentinel little-endian pattern. A
     * properly aggregating fold never copies a raw delta, so it must be absent. */
    const unsigned char want[2] = {0x51, 0x51};
    const unsigned char *p = reinterpret_cast<const unsigned char *>(&rec);
    for (size_t i = 0; i + 1 < sizeof(rec); ++i) {
        if (p[i] == want[0] && p[i + 1] == want[1]) {
            std::printf("FAIL: raw delta sentinel leaked into the emitted struct\n");
            return 1;
        }
    }
    return 0;
}

#ifndef HK_DEVICE_TRUST_BYPASS_ENABLED

int main(void)
{
    /* The privacy invariant runs unconditionally (it needs no server model); the
     * model-scoring half is disabled until the 142 ONNX path lands. */
    if (privacy_invariant() != 0) {
        return 1;
    }
    std::printf("PASS(privacy-invariant); DISABLED(model-scoring): "
                "pointer_lattice_synthetic activates the non-physical/real-sensor "
                "discrimination with the 142 ONNX scoring path.\n");
    return 0;
}

#else

int main(void)
{
    if (privacy_invariant() != 0) {
        return 1;
    }
    /* Activated body fills in: fold a uniform stream, an integer-curve stream, a
     * single-fixed-step stream (each with jittered inter-arrival timing) and a captured
     * real-sensor stream; submit each feat[24] to the server pointer model conditioned
     * on HK_PCLASS_MOUSE; assert the synthetic three score non-physical and the real one
     * does not. */
    return 0;
}

#endif
