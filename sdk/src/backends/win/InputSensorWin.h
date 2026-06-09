/*
 * sdk/src/backends/win/InputSensorWin.h
 * Role: SDK-internal façade for the Windows input-provenance usermode sensors
 *       (catalog signals 55-63, win-input-automation). Declares the nine sensor
 *       entry points, the shared raw-input device-inventory snapshot type, and the
 *       small PLATFORM-FREE decision cores (provenance classification, NULL/unknown
 *       ratio folding, RAWMOUSE/scan-code flag folding, timing-feature math,
 *       poll-rate derivation) that the host unit tests drive with no live process /
 *       no Win32. The Win32-touching builders/sensors are declared here and
 *       implemented in the *Win.cpp siblings.
 * Target platforms: Windows (userspace). The pure cores are platform-free so they
 *       are host-testable (mirrors RenderSensorWin.h / ThreadProvenanceWin.h).
 * Interface: implements the entry points consumed by the Windows sdk.cpp AC tick;
 *       implemented by RawInputInventoryWin.cpp + the nine *Win.cpp sensor files.
 *       Findings are emitted on the input JSON plane (input_prov_schema.h), never
 *       the kernel ring (guardrail #4 — no kernel TU includes this header).
 */

#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "horkos/input_prov_schema.h"

namespace hk { namespace sdk { namespace win {

/* -------------------------------------------------------------------------
 * Shared raw-input device inventory (signals 55/58/60/62).
 * One entry per enumerated raw-input device: the opaque per-session token assigned
 * to its hDevice (NOT the raw HANDLE — see plan R6), its RIDI_DEVICENAME interface
 * path, its top-level usage page/usage, and the derived transport. Built once on AC
 * start and refreshed on every WM_INPUT_DEVICE_CHANGE by RawInputInventoryWin.cpp;
 * the consuming sensors read it without any platform call so they are host-testable.
 * ------------------------------------------------------------------------- */
struct RawInputDevice {
    uint64_t    hdevice_token;   /* opaque per-session id; stable within a session only */
    std::string device_path;     /* RIDI_DEVICENAME device-interface path */
    uint16_t    usage_page;      /* RID_DEVICE_INFO top-level usage page (0x01 generic desktop) */
    uint16_t    usage;           /* usage (0x02 mouse, 0x06 keyboard) */
    uint32_t    transport_flags; /* HK_INTRANSPORT_* derived from RID_DEVICE_INFO/parent bus */
    bool        absolute_capable;/* an absolute-class HID (digitizer/touch) enumerated for it */
};

struct RawInputInventory {
    std::vector<RawInputDevice> devices; /* keyed by hdevice_token; small, linear scan */
};

/* -------------------------------------------------------------------------
 * Pure provenance classifier (signals 55/56/57). No platform calls — defined
 * inline so the host unit test exercises the full decision table with no live
 * process (mirrors classify_provenance in RenderSensorWin.h). Deliberately
 * conservative: an unresolved source is HK_INPUT_SRC_UNRESOLVED, never a fabricated
 * anomaly. The CLIENT only reports which bucket the resolved source falls in; the
 * server's signed allow-list rule fuses the rest (catalog: server alone decides).
 * ------------------------------------------------------------------------- */

/* The minimal source-resolution facts the platform sensor fills before classifying. */
struct InputSourceInput {
    bool query_failed;       /* a SetupAPI/HID/raw-input query failed -> UNRESOLVED */
    bool hdevice_null;       /* WM_INPUT hDevice == NULL */
    bool hdevice_unknown;    /* hDevice not present in the inventory */
    bool accessibility_gate; /* approved remote/accessibility session set (SM_REMOTESESSION etc.) */
    bool is_class_filter;    /* this is a class-filter finding (56) */
    bool filter_signed;      /* the filter image's Authenticode chain is valid */
    bool filter_allowlisted; /* server allow-list hit for the filter signer */
    bool is_hid_transport;   /* this is a HID-transport finding (57) */
    bool emulator_bridge;    /* HID usage over a serial/CDC/generic-bridge parent */
};

/* Classify a single resolved source into hk_input_verdict. Order matters: an
 * explicit query failure dominates (never guess), then the accessibility gate
 * (real-user safety floor, plan R7), then the filter/HID/raw-input buckets. */
inline hk_input_verdict classify_input_source(const InputSourceInput &in)
{
    if (in.query_failed) {
        return HK_INPUT_SRC_UNRESOLVED;
    }
    if (in.is_class_filter) {
        if (!in.filter_signed) {
            return HK_INPUT_SRC_FILTER_UNSIGNED;
        }
        if (!in.filter_allowlisted) {
            return HK_INPUT_SRC_FILTER_FOREIGN_SIGNED;
        }
        return HK_INPUT_SRC_PHYSICAL_KNOWN; /* signed + vendor-allowlisted filter is benign */
    }
    if (in.is_hid_transport) {
        return in.emulator_bridge ? HK_INPUT_SRC_EMULATOR_BRIDGE
                                  : HK_INPUT_SRC_PHYSICAL_KNOWN;
    }
    /* Raw-input source-handle reconciliation (55). A NULL/unknown hDevice with an
     * approved gate is benign; without a gate it is the synthetic shape. */
    if (in.hdevice_null || in.hdevice_unknown) {
        return in.accessibility_gate ? HK_INPUT_SRC_ACCESSIBILITY_GATED
                                     : HK_INPUT_SRC_SYNTHETIC;
    }
    return HK_INPUT_SRC_PHYSICAL_KNOWN;
}

/* -------------------------------------------------------------------------
 * Ratio folding (signal 55). The catalog mandate is to report the
 * anomaly/window RATIO, never a single event. Pure accumulator + a "does this
 * window cross the report threshold" predicate the host test drives.
 * ------------------------------------------------------------------------- */
struct RatioWindow {
    uint32_t event_count;   /* denominator */
    uint32_t anomaly_count; /* numerator (NULL/unknown hDevice events) */
};

/* True only when the window has enough samples AND a non-zero anomaly fraction.
 * `min_events` guards against a single stray NULL event flagging (catalog FP gate).
 * The actual scoring threshold is server-side; this only decides "emit a finding at
 * all" so a sparse benign window stays silent. */
inline bool ratio_window_reportable(const RatioWindow &w, uint32_t min_events)
{
    return w.event_count >= min_events && w.anomaly_count > 0 &&
           w.anomaly_count <= w.event_count;
}

/* -------------------------------------------------------------------------
 * RAWMOUSE / scan-code / extra-info flag folding (signals 60/63). Pure, so the
 * host test drives the bitmask, the relative<->absolute oscillation detection, and
 * the gameplay-context gating with no live WM_INPUT.
 * ------------------------------------------------------------------------- */

/* The RAWMOUSE.usFlags facts the raw-mouse sensor reads, per hDevice window. */
struct RawMouseModeInput {
    bool flag_absolute;        /* MOUSE_MOVE_ABSOLUTE this event */
    bool flag_virtual_desktop; /* MOUSE_VIRTUAL_DESKTOP this event */
    bool prior_was_relative;   /* the same hDevice reported MOUSE_MOVE_RELATIVE earlier in window */
    bool absolute_device_present; /* an absolute-class HID (digitizer/touch) actually enumerated */
    bool remote_session;       /* SM_REMOTESESSION true (RDP/VNC legitimately absolute) */
};

/* Fold RAWMOUSE facts into the HK_INFLAG_* bitmask. MODE_OSCILLATION is the derived
 * relative->absolute transition on a device with no absolute-class backing on a
 * local console — the catalog FP guards (Wacom/touch/RDP/VM) suppress it. */
inline uint32_t fold_rawmouse_flags(const RawMouseModeInput &in)
{
    uint32_t bits = 0;
    if (in.flag_absolute)        bits |= HK_INFLAG_MOUSE_ABSOLUTE;
    if (in.flag_virtual_desktop) bits |= HK_INFLAG_MOUSE_VIRTDESKTOP;
    if (in.remote_session)       bits |= HK_INFLAG_REMOTE_SESSION;
    /* Oscillation only when the device flipped relative->absolute, no absolute-class
     * device explains it, and we are on the local console (not RDP/VNC). */
    if (in.flag_absolute && in.prior_was_relative &&
        !in.absolute_device_present && !in.remote_session) {
        bits |= HK_INFLAG_MODE_OSCILLATION;
    }
    return bits;
}

/* The keyboard scan-code / extra-info / injected facts the synthetic-artifact
 * sensor reads in the game's own LL-hook path. */
struct SyntheticArtifactInput {
    bool scancode_zero;       /* KBDLLHOOKSTRUCT.scanCode == 0 (KEYEVENTF_UNICODE / synthesized) */
    bool extrainfo_unknown;   /* GetMessageExtraInfo matched no known driver stamp */
    bool llmhf_injected;      /* LLMHF_INJECTED / LLMHF_LOWER_IL_INJECTED baseline */
    bool gameplay_context;    /* SDK says in-combat / text entry not expected */
};

/* Fold synthetic-artifact facts into the HK_INFLAG_* bitmask. The gameplay-context
 * bit is set when present; the scan-code/extra-info bits are SOFT flags fused
 * server-side (catalog FP: clipboard paste, IME, OSK, Unicode entry all legitimately
 * produce scan-code-less KEYEVENTF_UNICODE). The client never decides a verdict here. */
inline uint32_t fold_synthetic_flags(const SyntheticArtifactInput &in)
{
    uint32_t bits = 0;
    if (in.scancode_zero)     bits |= HK_INFLAG_NO_SCANCODE;
    if (in.extrainfo_unknown) bits |= HK_INFLAG_EXTRAINFO_UNKNOWN;
    if (in.llmhf_injected)    bits |= HK_INFLAG_LLMHF_INJECTED;
    if (in.gameplay_context)  bits |= HK_INFLAG_GAMEPLAY_CONTEXT;
    return bits;
}

/* -------------------------------------------------------------------------
 * Timing-feature math (signals 58/62). Pure and the main correctness axis: feed a
 * sequence of inter-arrival deltas, get back the fixed timing-feature block.
 * FEATURES ONLY — there is deliberately no verdict output here (catalog: never a
 * client-side ban on timing). The server model thresholds; this never does.
 * ------------------------------------------------------------------------- */

/* Fold a sequence of inter-arrival deltas (in nanoseconds) into the histogram, CoV,
 * and a regularity score, writing them into `out`. `out.signal`/`hdevice_token`/
 * transport/declared/observed are set by the caller; this fills only the derived
 * statistics + sample_count + period_hist. `bucket_ns` is the histogram bin width.
 * Deterministic integer math (no float) so the host test pins exact values. Inline
 * (header-only) so the host unit test links it without the platform TU, mirroring
 * PeRelocate.h. */
inline void compute_timing_features(const uint64_t *deltas_ns, uint32_t count,
                                    uint64_t bucket_ns, hk_input_timing_features &out)
{
    for (uint32_t i = 0; i < HK_INPUT_TIMING_BUCKETS; ++i) {
        out.period_hist[i] = 0;
    }
    out.sample_count = count;
    out.cov_x10000 = 0;
    out.regularity_x10000 = 0;
    if (count == 0 || bucket_ns == 0) {
        return;
    }

    /* Histogram: clamp the top bucket so a long tail does not read OOB. */
    uint64_t sum = 0;
    for (uint32_t i = 0; i < count; ++i) {
        uint64_t b = deltas_ns[i] / bucket_ns;
        if (b >= HK_INPUT_TIMING_BUCKETS) {
            b = HK_INPUT_TIMING_BUCKETS - 1;
        }
        out.period_hist[(uint32_t)b] += 1;
        sum += deltas_ns[i];
    }

    const uint64_t mean = sum / count;
    if (mean == 0) {
        return;
    }

    /* Population variance via integer accumulation of squared deviations. Deltas are
     * sub-second, so squared deviations fit comfortably in uint64 across realistic
     * windows; this is deterministic and host-pinnable. */
    uint64_t var_acc = 0;
    for (uint32_t i = 0; i < count; ++i) {
        const int64_t dev = (int64_t)deltas_ns[i] - (int64_t)mean;
        var_acc += (uint64_t)(dev * dev);
    }
    const uint64_t variance = var_acc / count;

    /* Integer sqrt of the variance -> standard deviation. */
    uint64_t stddev = 0;
    {
        uint64_t x = variance;
        uint64_t r = 0;
        uint64_t bit = (uint64_t)1 << 62;
        while (bit > x) bit >>= 2;
        while (bit != 0) {
            if (x >= r + bit) {
                x -= r + bit;
                r = (r >> 1) + bit;
            } else {
                r >>= 1;
            }
            bit >>= 2;
        }
        stddev = r;
    }

    /* CoV = stddev / mean, fixed-point *1e4. A perfectly regular stream (stddev 0)
     * yields cov_x10000 == 0; high jitter approaches/exceeds 1e4. */
    out.cov_x10000 = (uint32_t)((stddev * 10000ull) / mean);

    /* Regularity score *1e4: inverse of CoV, clamped to [0, 1e4]. A fixed-period
     * macro (low CoV) scores near 1e4; physical tremor (high CoV) scores low. This
     * is a FEATURE for the server model, not a threshold (catalog mandate). */
    out.regularity_x10000 =
        out.cov_x10000 >= 10000u ? 0u : (10000u - out.cov_x10000);
}

/* -------------------------------------------------------------------------
 * Poll-rate derivation (signal 62). Pure: given a USB interrupt-IN endpoint
 * bInterval (or 0 = unknown) and a measured WM_INPUT arrival rate, derive declared
 * vs observed and decide whether the mismatch feature is even meaningful. A
 * Bluetooth/wireless/virtual transport suppresses the declared rate (exemption).
 * ------------------------------------------------------------------------- */

/* Derive declared_hz from a USB interrupt endpoint bInterval. For a full/low-speed
 * interrupt endpoint, bInterval is the polling period in milliseconds (rate =
 * 1000 / bInterval Hz); for high/super-speed it is an exponent: the period is
 * 2^(bInterval-1) microframes of 125 us each (rate = 8000 / 2^(bInterval-1) Hz). The
 * sensor only reaches here for USB transports; non-USB returns 0 (unknown). Returns
 * 0 when bInterval is 0/out-of-range so the server gets no contradiction feature
 * rather than a false one (plan R4). Inline/header-only for the host test. */
inline uint32_t declared_hz_from_binterval(uint8_t b_interval, bool high_speed)
{
    if (b_interval == 0) {
        return 0; /* unknown / not an interrupt endpoint -> no declared rate */
    }
    if (high_speed) {
        /* Valid high-speed interrupt bInterval is 1..16; reject out-of-range. */
        if (b_interval > 16) {
            return 0;
        }
        const uint32_t microframes = 1u << (uint32_t)(b_interval - 1);
        return 8000u / microframes;
    }
    /* Full/low speed: bInterval is the period in ms (1..255). */
    return 1000u / (uint32_t)b_interval;
}

/* True when the timing block carries a meaningful declared-vs-observed comparison.
 * A BLUETOOTH/WIRELESS/VIRTUAL transport, or a zero declared rate, makes the
 * comparison meaningless (exemption) and the server must not read a contradiction. */
inline bool pollrate_comparison_valid(const hk_input_timing_features &t)
{
    if (t.declared_hz == 0) {
        return false;
    }
    if (t.transport_flags &
        (HK_INTRANSPORT_BLUETOOTH | HK_INTRANSPORT_WIRELESS | HK_INTRANSPORT_VIRTUAL)) {
        return false;
    }
    return true;
}

#if defined(HK_PLATFORM_WINDOWS) || defined(_WIN32)

/* Build the per-session raw-input device inventory shared by 55/58/60/62. Returns
 * false on enumeration failure (the caller treats the tick as "no inventory"; every
 * dependent sensor then degrades to HK_INPUT_SRC_UNRESOLVED rather than guessing).
 * Read-only: GetRawInputDeviceList + GetRawInputDeviceInfoW. The (_WIN32 fallback in
 * the guard mirrors the other backends/win headers — the SDK has not yet defined
 * HK_PLATFORM_WINDOWS for this TU, but the implementation lives strictly under
 * backends/win/ per guardrail #1.) */
bool build_rawinput_inventory(RawInputInventory &out);

/* The nine sensor entry points. Each appends zero or more records to the relevant
 * output vector and returns the number appended, or -1 on a sensor-level failure
 * (itself reported as an HK_INPUT_SRC_UNRESOLVED finding, not a silent drop). All
 * are read-only — they observe only the GAME's own input + system device topology
 * (no foreign-process hooking, no injection, no unhooking) — and must not let an
 * exception cross this C++ ABI seam. */
int sense_rawinput_provenance(const RawInputInventory &inv,
                              std::vector<hk_input_finding> &out);
int sense_input_class_filters(std::vector<hk_input_finding> &out);
int sense_hid_transport(std::vector<hk_input_finding> &out);
int sense_input_timing(const RawInputInventory &inv,
                       std::vector<hk_input_timing_features> &out);
int sense_llhook_chain(std::vector<hk_input_finding> &out);
int sense_rawmouse_mode(const RawInputInventory &inv,
                        std::vector<hk_input_finding> &out);
int sense_input_queue_attach(std::vector<hk_input_finding> &out);
int sense_hid_pollrate(const RawInputInventory &inv,
                       std::vector<hk_input_timing_features> &out);
int sense_synthetic_artifact(std::vector<hk_input_finding> &out);

#endif /* HK_PLATFORM_WINDOWS || _WIN32 */

} } } // namespace hk::sdk::win
