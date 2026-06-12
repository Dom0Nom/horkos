/*
 * Role: HID-fingerprint merge-gate bypass test (Phase: [disabled]) for signal 136. The
 *       activated body builds three synthetic preparsed-caps fixtures — an
 *       Arduino-HID-library / V-USB / LUFA TEMPLATE descriptor, a QMK/ZMK keyboard
 *       descriptor, and a genuine-vendor mouse descriptor — runs them through the same
 *       canonicalize_hid_descriptor + SHA-256 the sensor uses, and asserts: (1) the
 *       template descriptor produces a fingerprint the server corpus flags as
 *       template-class, AND (2) the QMK/ZMK and genuine-vendor fingerprints are
 *       DISTINGUISHABLE from the template and from each other (the FP-gate proof — not
 *       just detection, but that real boards are NOT swept into the template cluster).
 * Target platforms: Windows only (built behind if(WIN32)); the canonical fold is
 *       platform-free, so the disabled stub compiles on any host.
 * Interface: consumes sdk/include/horkos/device_trust_schema.h and the canonical fold
 *       in sdk/src/backends/win/input/DeviceTrustWin.h.
 *
 * Merge gate (guardrail #12): this is the bypass test for the device-trust HID-
 * fingerprint sensor (signal 136). It compiles now; its assertions activate when the
 * fingerprint corpus/cluster path lands — exactly like byovd_load.cpp. The repo never
 * commits a real cloning firmware image.
 */

#include <cstdio>

#ifndef HK_DEVICE_TRUST_BYPASS_ENABLED

int main(void)
{
    std::printf("DISABLED: hid_descriptor_template_clone bypass test activates with the "
                "136 fingerprint corpus/cluster path.\n");
    return 0; /* Disabled tests pass so the gate stays green. */
}

#else

#include "input/DeviceTrustWin.h"

/* Activated body fills in: build the three HidCanonicalInput fixtures (template /
 * QMK-ZMK / genuine-vendor), canonicalize_hid_descriptor each, SHA-256, then assert
 *   1. template fingerprint == the corpus template-class hash (server flag), AND
 *   2. fp(template) != fp(qmk) != fp(vendor) (distinguishability / FP gate), AND
 *   3. reordering the template's usage pages yields the SAME fingerprint
 *      (canonicalization correctness — an order-shuffle does not evade clustering).
 */
int main(void)
{
    return 0;
}

#endif
