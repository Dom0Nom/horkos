/*
 * Role: Linux bypass-test fixture (merge gate, guardrail #12) for signal 90
 *       (text COW-broken). Demonstrates: patch a byte in a loaded DSO's .text
 *       (break COW) -> signal 90 fires; an IFUNC-prologue dirty page -> no event
 *       (proves the IFUNC/reloc-span suppression). The span-suppression half is
 *       the load-bearing assertion. Compiled now for the gate; assertions
 *       activate once text_sample + TextPageBacking land on-box.
 * Target platforms: Linux only (built behind if(UNIX AND NOT APPLE)).
 * Interface: drives the loader event sink (signal 90) once it lands.
 */

#include <cstdio>

#ifndef HK_TEXT_HOOK_TEST_ENABLED

int main(void) {
    std::printf("DISABLED: text_inline_hook activates once text_sample + "
                "TextPageBacking land on-box (signal 90 default-OFF; pagemap caps "
                "flagged).\n");
    return 0;
}

#else

int main(void) {
    /* On-box fill-in:
     *   1. mprotect a loaded DSO's .text RW, patch one byte (breaks COW), restore.
     *   2. Trigger the sample; assert HK_EVENT_TEXT_PATCH fired (Private_Dirty>0).
     *   3. Dirty only an IFUNC-prologue page covered by an allowed span; assert
     *      NO event. */
    std::printf("text_inline_hook: enforcement path not yet implemented.\n");
    return 1;
}

#endif /* HK_TEXT_HOOK_TEST_ENABLED */
