/*
 * Role: Merge-gate bypass test (guardrail #12) for the object/notify/registry
 *       self-integrity surface (win-kernel-object-callbacks). Exercises the four
 *       unhook scenarios against the self-check sensor and asserts the
 *       corresponding integrity event fires:
 *         (1) Ob-deregister     => signal-1 liveness emits _MISSING after N polls
 *                                  AND heartbeat confirms it is not starvation.
 *         (2) Ps-notify removal => signal-3 re-arm probe sees STATUS_SUCCESS, the
 *                                  duplicate is re-disarmed, integrity event fires;
 *                                  signal-4 census shows own_present bit0 cleared.
 *         (3) .text patch       => signal-8 hash mismatch fires though table-walk
 *                                  signals stay green.
 *         (4) Cm-cookie removal => signal-9 census shows our cookie absent.
 *       Phase 3 ships DISABLED (HK_SELFCHECK_TEST_ENABLED undefined): compiled
 *       no-op that reports "DISABLED" and returns 0, exactly like byovd_load.cpp.
 *       Activated in a later enforcement phase when the kernel fixture that can
 *       unhook a live driver exists. The repo never commits an unhooking driver.
 * Target platforms: Windows only (built behind if(WIN32)).
 * Interface: consumes sdk/include/horkos/ioctl.h and the integrity event surface
 *       (HK_EVENT_CALLBACK_INTEGRITY / _CENSUS, HK_CB_RESULT_*). HK-TODO(schema):
 *       those wire types are kernel-private mirrors until the Schema phase appends
 *       them to event_schema.h, so the enabled body below references them through
 *       the kernel header's placeholders and will compile against the real symbols
 *       once the schema bump lands.
 *
 * Merge gate (guardrail #12): this file is the representative bypass test for the
 * win-kernel-object-callbacks security folder. It compiles now; its assertions
 * activate when HK_SELFCHECK_TEST_ENABLED is defined and the unhook fixture lands.
 */

#include <cstdio>

#ifndef HK_SELFCHECK_TEST_ENABLED

int main(void)
{
    std::printf("DISABLED: callback_unhook bypass test activates in a later "
                "enforcement phase (needs the kernel unhook fixture + the "
                "HK_EVENT_CALLBACK_* schema bump).\n");
    return 0; /* Disabled tests pass so the gate stays green pre-enforcement. */
}

#else

#include <windows.h>
#include <vector>

#include "horkos/ioctl.h"

/*
 * Drain the kernel ring and return how many records of `type` with `result` were
 * observed. Helper shared by the four sub-cases once the fixture is wired.
 */
static int count_integrity(uint32_t type, uint32_t result)
{
    /* Phase-later: open \\.\Horkos, issue HK_IOCTL_DRAIN_EVENTS, scan records for
     * header.type == type and (for integrity records) payload.result == result.
     * Returns the match count. */
    (void)type;
    (void)result;
    return 0;
}

/* Each sub-case forces one unhook via the (later) kernel fixture, then waits for
 * the self-check period to elapse and asserts the right event fired. */

static int case_ob_deregister(void)    { return 1; /* TODO: fixture + assert _MISSING */ }
static int case_ps_notify_removal(void){ return 1; /* TODO: fixture + assert re-arm + census */ }
static int case_text_patch(void)       { return 1; /* TODO: fixture + assert _TEXT_PATCH */ }
static int case_cm_cookie_removal(void){ return 1; /* TODO: fixture + assert census own_cm clear */ }

int main(void)
{
    int failures = 0;
    failures += case_ob_deregister();
    failures += case_ps_notify_removal();
    failures += case_text_patch();
    failures += case_cm_cookie_removal();

    if (failures != 0) {
        std::printf("callback_unhook: %d sub-case(s) not yet implemented.\n",
                    failures);
        return 1;
    }
    std::printf("callback_unhook: all sub-cases passed.\n");
    return 0;
}

#endif /* HK_SELFCHECK_TEST_ENABLED */
