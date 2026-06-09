/*
 * bypass-tests/win/etwti_teardown.cpp
 * Role: Merge-gate bypass test (guardrail #12) for signal 212 (ETW-TI provider
 *       liveness, win-kernel-syscall-etw-integrity). A Phase-5 fixture nulls
 *       EtwThreatIntProvRegHandle (or otherwise silences the TI feed); the AC must
 *       emit the version-independent keepalive half HK_INTEGRITY_ETWTI_NO_KEEPALIVE
 *       even when the raw-handle read is UNVERIFIABLE — proving the keepalive half
 *       stands alone without resolving any unexported global. Ships DISABLED
 *       (HK_INTEGRITY_TEST_ENABLED undefined): a compiled no-op returning 0, like
 *       byovd_load.cpp.
 * Target platforms: Windows only (built behind if(WIN32)).
 * Interface: consumes sdk/include/horkos/ioctl.h and the integrity event surface
 *       (HK_INTEGRITY_ETWTI_NO_KEEPALIVE / _ETWTI_DOWN). HK-TODO(schema):
 *       kernel-private mirrors until the Schema phase appends them.
 *       HK-UNCERTAIN(etw-ti-consumer): the keepalive only fires once a real ETW-TI
 *       consumer exists (PPL/ELAM-gated) — this assertion activates with that
 *       consumer, not before.
 */

#include <cstdio>

#ifndef HK_INTEGRITY_TEST_ENABLED

int main(void)
{
    std::printf("DISABLED: etwti_teardown activates in Phase 5 (needs the TI "
                "teardown fixture, a real ETW-TI consumer for the keepalive, + "
                "HK_EVENT_INTEGRITY_FINDING schema bump).\n");
    return 0;
}

#else

#include <windows.h>

#include "horkos/ioctl.h"
#include "horkos_kernel.h" /* HK_INTEGRITY_ETWTI_NO_KEEPALIVE mirror */

static int count_findings(uint32_t finding)
{
    (void)finding;
    return 0;
}

int main(void)
{
    /* The version-independent keepalive half must fire even with the raw handle
     * unverifiable. */
    if (count_findings(HK_INTEGRITY_ETWTI_NO_KEEPALIVE) < 1) {
        std::printf("etwti_teardown: expected ETWTI_NO_KEEPALIVE not observed.\n");
        return 1;
    }
    std::printf("etwti_teardown: passed.\n");
    return 0;
}

#endif /* HK_INTEGRITY_TEST_ENABLED */
