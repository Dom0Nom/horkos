/*
 * Role: Linux raw-HID aim sampler (catalog signals 163/164/165). Reads the GAME'S
 *       OWN evdev node for relative-motion reports (EV_REL REL_X/REL_Y), stamping
 *       each with a monotonic timestamp (input_event.time / clock_gettime
 *       CLOCK_MONOTONIC_RAW) into platform-free hk_hid_sample records that the
 *       platform-neutral AimAccumulator.fold_tick collapses into the 163/165
 *       features. USERSPACE evdev only — NOT the eBPF/LKM kernel plane.
 * Target platforms: Linux userspace. Guardrail #1: the evdev read()/ioctl path is
 *       confined to this backend; the fold/decision is platform-free
 *       (AimAccumulator.cpp / aim_kinematics.rs, host-tested). Guardrail #4: this
 *       shares no TU with kernel/linux/ and includes no .bpf.c header.
 * Interface: implements hk::sdk::aim::sample_raw_hid from input/AimSampler.h.
 *       Catalog slots 163/164/165. Reads only the game's own input device; never
 *       injects.
 *
 * HK-UNCERTAIN(evdev-node-access): reading /dev/input/event* requires the `input`
 * group or an equivalent ACL, and the SDK must resolve WHICH node is the active
 * aim device (the game's grabbed pointer) before draining it. That node-selection
 * + permission path is SDK/loader integration owned elsewhere and is not wired
 * here; the live read shape is documented below but no fd is opened. Per
 * guardrail #13 the access path is not guessed (plan R6); with no resolved node
 * this drains nothing rather than fabricating reports.
 */

#include "input/AimSampler.h"

#include "platform.h"

#if defined(HK_PLATFORM_LINUX) || defined(__linux__)

#include <cstdint>

namespace hk { namespace sdk { namespace aim {

uint32_t sample_raw_hid(hk_hid_sample* samples, uint32_t cap)
{
    if (samples == nullptr || cap == 0) {
        return 0;
    }

    /* HK-UNCERTAIN(evdev-node-access): no resolved evdev fd this tick (see file
     * header). The live per-report drain, once the SDK supplies the non-blocking
     * fd for the game's grabbed aim device:
     *
     *   struct input_event ev;
     *   int32_t dx = 0, dy = 0; bool moved = false;
     *   while (read(fd, &ev, sizeof(ev)) == (ssize_t)sizeof(ev)) {  // O_NONBLOCK
     *       if (ev.type == EV_REL) {
     *           if (ev.code == REL_X) { dx += ev.value; moved = true; }
     *           else if (ev.code == REL_Y) { dy += ev.value; moved = true; }
     *       } else if (ev.type == EV_SYN && ev.code == SYN_REPORT && moved) {
     *           struct timespec ts; clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
     *           samples[written].raw_dx   = dx;
     *           samples[written].raw_dy   = dy;
     *           samples[written].ts_ns    = (uint64_t)ts.tv_sec * 1000000000ull
     *                                       + (uint64_t)ts.tv_nsec;
     *           samples[written].injected = 0; // 171 sets virtual-source per uinput
     *           ++written; dx = dy = 0; moved = false;
     *           if (written == cap) break;
     *       }
     *   }
     *   return written;
     *
     * (input_event.time is the alternative hardware stamp; CLOCK_MONOTONIC_RAW is
     * used for a single monotonic basis shared with the framelock comparison.)
     * With no fd, write nothing — a zero-count tick is a true "no HID", not an
     * anomaly (catalog FP gate). */
    (void)samples;
    (void)cap;
    return 0; /* no resolved evdev node this tick: nothing drained */
}

} } } // namespace hk::sdk::aim

#endif /* HK_PLATFORM_LINUX || __linux__ */
