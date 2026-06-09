/*
 * sdk/src/backends/win/InputFrameProbeWin.cpp
 * Role: Signal 185 — raw-input frame timestamp-coherence sensor. Correlates the
 *       OS-capture timestamps of the game's outbound input frames (GetMessageTime /
 *       GetRawInputData RAWINPUT) against their send sequence and flags
 *       non-monotonic / duplicate / backdated frames; GetCurrentInputMessageSource
 *       tags injected-vs-hardware origin as a SOFT flag (scored server-side, never a
 *       verdict — legitimate macro/remap/remote-desktop software synthesizes input).
 *       Read-only: never injects or rewrites input. All Win32 API confined to this
 *       backends/win/ TU (guardrail #1). Usermode (PASSIVE_LEVEL); no kernel TU.
 * Target platforms: Windows.
 * Interface: implements `hk::net::probe_input_frames` (185) from `net_probes.h`.
 *
 * Cannot be compiled on the macOS dev host; written against the impl-plan +
 * sibling backends/win sources.
 */

#include <windows.h>

#include "horkos/net_timing.h"
#include "net_probes.h"

#include <cstdint>

namespace hk { namespace net {

namespace {

/* The game publishes each consumed input frame's OS-capture timestamp (the
 * GetMessageTime value, ms tick, for the message that produced the frame) in send
 * order. We keep a small bounded window and fold the coherence flags over it. The
 * monotonic/duplicate/backdated checks are pure arithmetic over these published
 * timestamps — no OS call here beyond what the game already did to obtain them, so
 * this fold is verifiable on its own. */
constexpr int kWindow = 64;

uint32_t g_ts[kWindow] = {0};
uint32_t g_origin_synthetic[kWindow] = {0}; /* 1 if GetCurrentInputMessageSource said injected */
int      g_count = 0;
uint32_t g_window_start_ts = 0;
bool     g_have_window_start = false;

} // namespace

/* Reset the per-window accumulator. Called once at the start of each upload window
 * by the SDK input owner. */
void hk_net_input_window_begin(uint32_t window_start_ts)
{
    g_count = 0;
    g_window_start_ts = window_start_ts;
    g_have_window_start = true;
}

/* Publish one consumed input frame. `capture_ts` is the GetMessageTime value;
 * `source_is_synthetic` is the GetCurrentInputMessageSource verdict for the
 * message (soft). The game (not this TU) makes those two reads at the point it
 * dequeues the message; we only fold them. */
void hk_net_input_frame(uint32_t capture_ts, uint32_t source_is_synthetic)
{
    if (g_count < kWindow) {
        g_ts[g_count] = capture_ts;
        g_origin_synthetic[g_count] = source_is_synthetic ? 1u : 0u;
        ++g_count;
    }
    /* When the window is full, additional frames are dropped from the coherence
     * fold (the window is a sample, not a complete log) — never an error. */
}

hk_net_input_frame_coherence probe_input_frames(void)
{
    hk_net_input_frame_coherence out;
    out.input_frame_anomaly_flags = 0;

    uint32_t flags = 0;
    uint32_t prev = 0;
    bool have_prev = false;

    for (int i = 0; i < g_count; ++i) {
        const uint32_t ts = g_ts[i];

        if (g_have_window_start && ts != 0) {
            /* Backdated: a frame whose capture timestamp predates the window start.
             * GetMessageTime is a 32-bit ms tick that wraps ~49.7 days; we treat a
             * value strictly before the window start (within a half-range guard) as
             * backdated, ignoring the wrap boundary conservatively. */
            const uint32_t delta = ts - g_window_start_ts; /* modular */
            if (delta > 0x80000000u) { /* ts is "before" window start, mod 2^32 */
                flags |= HK_NET_INPUT_BACKDATED;
            }
        }

        if (have_prev) {
            if (ts == prev) {
                flags |= HK_NET_INPUT_DUPLICATE_TS;
            } else {
                /* Non-monotonic: capture time went backwards in send order
                 * (modular compare, half-range guard for the 49.7-day wrap). */
                const uint32_t d = ts - prev;
                if (d > 0x80000000u) {
                    flags |= HK_NET_INPUT_NONMONOTONIC;
                }
            }
        }

        /* HK-UNCERTAIN(win-input-source-fidelity): whether
         * GetCurrentInputMessageSource reliably distinguishes hardware from EVERY
         * class of synthetic input is not certain — some remote-desktop /
         * accessibility stacks may present as hardware (impl-plan Risks: 185).
         * Treated strictly as a SOFT flag (0x8), scored server-side, never a
         * standalone verdict. The game supplies the per-frame verdict; we only OR
         * it in. */
        if (g_origin_synthetic[i]) {
            flags |= HK_NET_INPUT_SYNTHETIC_ORIG;
        }

        prev = ts;
        have_prev = true;
    }

    out.input_frame_anomaly_flags = flags;
    return out;
}

} } // namespace hk::net
