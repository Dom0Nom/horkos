/*
 * Role: network-anomaly input-frame-coherence merge-gate bypass test (signal 185)
 *       [disabled]. When enabled: a replayed/duplicated input frame breaks the
 *       OS-capture (GetMessageTime) monotonic-timestamp invariant and sets the
 *       anomaly flag (non-monotonic / duplicate / backdated); a hardware-origin frame
 *       does not. The synthetic-origin bit (0x8) is soft (server-scored). Compiled now
 *       for the merge gate (guardrail #12).
 * Target platforms: Windows only (built behind if(WIN32)).
 * Interface: drives hk::net::probe_input_frames (InputFrameProbeWin.cpp).
 */
#include <cstdio>
#ifndef HK_NET_BYPASS_ENABLED
int main(void) {
    std::printf("DISABLED: net_inputframe activates with the SDK input-frame "
                "timestamp-stream integration + the replay fixture.\n");
    return 0;
}
#else
int main(void) {
    std::printf("net_inputframe: replayed-frame coherence fixture not yet implemented.\n");
    return 1;
}
#endif
