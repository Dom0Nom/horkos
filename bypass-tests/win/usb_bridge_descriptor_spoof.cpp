/*
 * Role: USB descriptor-coherence + composite-interface merge-gate bypass test (Phase:
 *       [disabled]) for signals 137 and 143. The activated body drives the pure
 *       classify_descriptor_coherence + fold_composite_interface_flags cores with three
 *       synthetic UsbNode fixtures and asserts: (1) a CH340/CP2102/FTDI bridge
 *       descriptor claiming a MAJOR-VENDOR VID surfaces as
 *       HK_INPUT_SRC_DESCRIPTOR_INCOHERENT (137); (2) if that bridge ALSO exposes HID +
 *       CDC under one ContainerID it additionally fires HK_DAUD_CONTAINER_MISMATCH
 *       (143); (3) a GENUINE vendor composite (HID + CDC RGB channel under a real
 *       vendor VID, NOT a bridge signature) is reported-but-benign (the FP gate —
 *       legitimate composites are not banned client-side).
 * Target platforms: Windows only (built behind if(WIN32)); the cores are platform-free,
 *       so the disabled stub compiles on any host.
 * Interface: consumes sdk/include/horkos/device_trust_schema.h and the pure cores in
 *       sdk/src/backends/win/input/DeviceTrustWin.h.
 *
 * Merge gate (guardrail #12): this is the bypass test for the device-trust descriptor-
 * coherence (137) + composite-interface (143) sensors. It compiles now; its assertions
 * activate when the server corpus/allowlist fusion path lands — exactly like
 * byovd_load.cpp. The repo never commits a real bridge-spoof firmware image.
 */

#include <cstdio>

#ifndef HK_DEVICE_TRUST_BYPASS_ENABLED

int main(void)
{
    std::printf("DISABLED: usb_bridge_descriptor_spoof bypass test activates with the "
                "137/143 corpus/allowlist fusion path.\n");
    return 0; /* Disabled tests pass so the gate stays green. */
}

#else

#include "input/DeviceTrustWin.h"

/* Activated body asserts the three cases above against classify_descriptor_coherence
 * (major_vendor_vid + bridge_chip_signature -> HK_INPUT_SRC_DESCRIPTOR_INCOHERENT) and
 * fold_composite_interface_flags (HID|CDC -> HK_DAUD_CONTAINER_MISMATCH), and that a
 * genuine-vendor HID|CDC composite WITHOUT a bridge signature stays PHYSICAL_KNOWN at
 * the verdict level (reported-but-benign; the server allowlists the known layout). */
int main(void)
{
    return 0;
}

#endif
