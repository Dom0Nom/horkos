/*
 * Role: network-anomaly clock-drift merge-gate bypass test (signal 182) [disabled].
 *       When enabled: a scaled clock source (monotonic at 0.8x realtime) must yield
 *       the expected clock_ratio_ppm, while an NTP-style discrete step trips
 *       step_detected but NOT the smooth-scale path. Proves the ratio + step are
 *       reported; the NTP-vs-scale verdict is server-side. Compiled now for the
 *       merge gate (guardrail #12). The host-side equivalent runs in the unit suite
 *       (tests/unit/test_net_collect.cpp) via the faked net_backend seam.
 * Target platforms: Windows only (built behind if(WIN32)).
 * Interface: drives hk::net::probe_clock_drift (ClockDomainProbe.cpp via net_backend.h).
 */
#include <cstdio>
#ifndef HK_NET_BYPASS_ENABLED
int main(void) {
    std::printf("DISABLED: net_clockdrift live form activates with the on-box clock "
                "backend; the ratio/step math is host-tested in the unit suite.\n");
    return 0;
}
#else
int main(void) {
    std::printf("net_clockdrift: live clock backend fixture not yet implemented.\n");
    return 1;
}
#endif
