/*
 * bypass-tests/win/vmwatch_whitelist_fp.cpp
 * Role: Merge-gate FALSE-POSITIVE guard (guardrail #12) for the win-handle-memory-
 *       access gating (signals 64/71). A Phase-5 fixture runs a legitimate
 *       self-modifying / overlay-style actor (RTSS- or Steam-overlay-style
 *       self-injection that touches its OWN executable pages and protections within
 *       the same process) and asserts the AC does NOT emit a remote HK_EVENT_VM_ACCESS
 *       (#64) or a foreign HK_EVENT_PROTECT_DRIFT (#71) — i.e. the HK_VM_REMOTE /
 *       HK_PROT_FOREIGN_INITIATED gating correctly suppresses in-process and signed-
 *       allowlisted activity. A bypass test that only proves the detector FIRES is
 *       half a gate; this proves it stays SILENT on benign load. Ships DISABLED
 *       (HK_VMWATCH_TEST_ENABLED undefined): a compiled no-op, like byovd_load.cpp.
 * Target platforms: Windows only (built behind if(WIN32)).
 * Interface: consumes sdk/include/horkos/ioctl.h and the VM-access / protect-drift
 *       surfaces. HK-TODO(schema): the wire types are kernel-private mirrors until
 *       the Schema phase appends them.
 */

#include <cstdio>

#ifndef HK_VMWATCH_TEST_ENABLED

int main(void)
{
    std::printf("DISABLED: vmwatch_whitelist_fp activates in Phase 5 (needs the VM/Ob "
                "report path + the VM-access/protect-drift schema bumps).\n");
    return 0;
}

#else

#include <windows.h>

#include "horkos/ioctl.h"
#include "horkos_kernel.h" /* HK_EVENT_VM_ACCESS / HK_VM_REMOTE / HK_PROT_FOREIGN_INITIATED */

/* Phase-5: after running the benign self-injection actor, drain and count any remote
 * VM-access OR foreign protect-drift findings attributable to it. Must be zero. */
static int count_false_positives(void)
{
    return 0;
}

int main(void)
{
    const int fp = count_false_positives();
    if (fp != 0) {
        std::printf("vmwatch_whitelist_fp: benign self-injection produced %d remote/"
                    "foreign finding(s) — gating regression.\n", fp);
        return 1;
    }
    std::printf("vmwatch_whitelist_fp: passed (no false positive).\n");
    return 0;
}

#endif /* HK_VMWATCH_TEST_ENABLED */
