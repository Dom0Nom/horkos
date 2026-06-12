/*
 * Role: Signal 139 — USB interrupt-endpoint poll-interval-coherence sensor. For each
 *       UsbTopology node with an interrupt-IN endpoint, derives the descriptor-
 *       permitted report-rate ceiling from bInterval + speed (reusing the sibling
 *       declared_hz_from_binterval mapping) and computes observed_rate / ceiling as a
 *       FEATURE (never a verdict). A wireless dongle re-clocks the endpoint, so the
 *       comparison is suppressed (HK_CAD_WIRELESS_EXEMPT). The observed sustained rate
 *       comes from the WM_INPUT QPC cadence accumulator (sibling raw-input path); the
 *       server thresholds the ratio.
 * Target platforms: Windows userspace.
 * Interface: implements hk::sdk::win::sense_poll_interval from input/DeviceTrustWin.h;
 *       emits hk_pointer_cadence_features (139 ceiling fields). Reuses the pure
 *       compute_cadence_ceiling core + declared_hz_from_binterval (InputSensorWin.h).
 */

#include "InputSensorWin.h"      /* declared_hz_from_binterval (sibling pure core) */
#include "input/DeviceTrustWin.h"

#if defined(HK_PLATFORM_WINDOWS) || defined(_WIN32)

#include <vector>

namespace hk { namespace sdk { namespace win {

namespace {

/* Observed sustained report rate (Hz) for a USB node, keyed by its container token.
 *
 * HK-UNCERTAIN(observed-rate-join): the sustained observed report rate is produced by
 * the sibling win-input-automation WM_INPUT QPC cadence accumulator (signal 62 timing
 * path), which keys its samples by hDevice_token, NOT by the USB container_token this
 * snapshot uses. The token-correlation seam (hDevice <-> ContainerID) is not yet wired
 * (it needs the on-box raw-input <-> SetupAPI device-path join). Until that join lands,
 * this returns 0 (no observed rate), so compute_cadence_ceiling emits an inconclusive
 * feature rather than a fabricated ratio. Per guardrail #13 the join is left a stub;
 * the on-box implementer connects the sibling cadence store here. */
float ObservedRateHzForNode(const UsbNode &node)
{
    (void)node;
    return 0.0f;
}

} // namespace

int sense_poll_interval(const UsbTopology &topo,
                        std::vector<hk_pointer_cadence_features> &out)
{
    int emitted = 0;
    for (const UsbNode &n : topo.nodes) {
        hk_pointer_cadence_features rec{};
        rec.schema_version = HK_DEVICE_TRUST_SCHEMA_VERSION;
        rec.hdevice_token = n.container_token;

        if (n.query_failed || n.in_interrupt_binterval == 0) {
            rec.flags |= HK_CAD_INCONCLUSIVE;
            out.push_back(rec);
            ++emitted;
            continue;
        }

        /* Descriptor ceiling: the maximum compliant report rate the endpoint's
         * bInterval permits. declared_hz_from_binterval returns 0 on an out-of-range
         * bInterval, which compute_cadence_ceiling treats as inconclusive. */
        const uint32_t ceiling_hz =
            declared_hz_from_binterval(n.in_interrupt_binterval, n.high_speed != 0);

        const float observed = ObservedRateHzForNode(n);
        compute_cadence_ceiling(observed, ceiling_hz, n.wireless_dongle != 0, rec);

        out.push_back(rec);
        ++emitted;
    }
    return emitted;
}

} } } // namespace hk::sdk::win

#endif /* HK_PLATFORM_WINDOWS || _WIN32 */
