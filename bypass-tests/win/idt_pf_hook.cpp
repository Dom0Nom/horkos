/*
 * Role: Merge-gate bypass test (guardrail #12) for signal 214 (IDT gate handler
 *       bounds, win-kernel-syscall-etw-integrity). A Phase-5 test-signed fixture
 *       detours a #PF/#DB IDT gate out of the kernel image; the AC must emit
 *       HK_INTEGRITY_IDT_OOI with the right (cpu << 8 | gate) in payload.detail.
 *       Ships DISABLED (HK_INTEGRITY_TEST_ENABLED undefined): a compiled no-op
 *       returning 0, like byovd_load.cpp. The repo never commits an IDT-detouring
 *       driver.
 * Target platforms: Windows only (built behind if(WIN32)).
 * Interface: consumes sdk/include/horkos/ioctl.h and the integrity event surface
 *       (HK_INTEGRITY_IDT_OOI). HK-TODO(schema): kernel-private mirrors until the
 *       Schema phase appends them.
 */

#include <cstdio>

#ifndef HK_INTEGRITY_TEST_ENABLED

int main(void)
{
    std::printf("DISABLED: idt_pf_hook activates in Phase 5 (needs the "
                "test-signed IDT-detour fixture + HK_EVENT_INTEGRITY_FINDING "
                "schema bump).\n");
    return 0;
}

#else

#include <windows.h>

#include "horkos/ioctl.h"
#include "horkos_kernel.h" /* HK_INTEGRITY_IDT_OOI mirror */

static int count_findings(uint32_t finding)
{
    (void)finding;
    return 0;
}

int main(void)
{
    if (count_findings(HK_INTEGRITY_IDT_OOI) < 1) {
        std::printf("idt_pf_hook: expected IDT_OOI not observed.\n");
        return 1;
    }
    std::printf("idt_pf_hook: passed.\n");
    return 0;
}

#endif /* HK_INTEGRITY_TEST_ENABLED */
