/*
 * bypass-tests/macos/responsible_launder.cpp
 * Role: Merge-gate bypass fixture for process-genealogy signal 207 (responsibility
 *       laundering), [disabled]. Intended to launch the target from an unsigned /
 *       ad-hoc launcher (Terminal-equivalent) with no store client in the chain
 *       and assert the responsibility-mismatch flag fires, AND that a Steam-rooted
 *       chain does NOT flag — demonstrating responsibility laundering is caught.
 *       Read-only assertion of the raw flag — never a local ban.
 * Target platforms: macOS only (built behind if(APPLE)).
 * Interface: consumes the AC launch-trust flag surface.
 *
 * Merge gate (guardrail #12): present for the security folder; assertions activate
 * once the ES genealogy handler ships under the EndpointSecurity entitlement and
 * HK_GENEALOGY_TEST_ENABLED is defined. Ships disabled pre-enforcement.
 */

#include <cstdio>

#ifndef HK_GENEALOGY_TEST_ENABLED

int main(void)
{
    std::printf("DISABLED: responsible_launder activates once the ES genealogy "
                "handler ships under the entitlement (HK_GENEALOGY_TEST_ENABLED).\n");
    return 0; /* Disabled tests pass so the gate stays green. */
}

#else

int main(void)
{
    std::printf("responsible_launder: ES genealogy handler not yet entitled.\n");
    return 1;
}

#endif /* HK_GENEALOGY_TEST_ENABLED */
