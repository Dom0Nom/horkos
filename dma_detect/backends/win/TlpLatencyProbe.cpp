/*
 * dma_detect/backends/win/TlpLatencyProbe.cpp
 * Role: Windows config-read TLP latency probe (sig 132 — LOW WEIGHT side-channel).
 *       Intended to tight-loop identical config reads of one register timed with
 *       QueryPerformanceCounter, build robust stats (median + IQR), and tag the
 *       same-root-port peer cohort. NEVER fires standalone; explicitly low-weight.
 * Target platforms: Windows only. Selected by CMake if(WIN32); linked into
 *       hk_dma_detect.
 * Implements: hk_dma_win_fill_tlp_latency (an opt-in pass; symmetric with the
 *       Linux hk_dma_linux_fill_tlp_latency entry point).
 *
 * *** HK-UNCERTAIN(win-config-read): the latency side-channel TIMES a config-space
 * read; it therefore depends on the SAME unconfirmed userspace config-read path as
 * MSI-X / ext-config (impl-plan Risk #1). Without a confirmed userspace GetBusData
 * route there is no register to time from userspace, so this arm is deferred. Sig
 * 132 is the lowest-value, highest-noise signal (impl-plan §sequencing #7) and
 * never fires standalone, so deferring it on Windows costs the least. The robust
 * median/IQR math is trivial and lives in the Linux arm; it is re-added here once
 * the config-read primitive is confirmed on-box. ***
 */

#include <windows.h>
#include <cstdint>

#include "../../include/horkos/dma_forensics.h"

/* -------------------------------------------------------------------------
 * hk_dma_win_fill_tlp_latency
 *
 * HK-UNCERTAIN(win-config-read): deferred — leaves the latency fields 0 ("no
 * sample"). The server already treats a zero median/IQR as "not measured", never
 * as a fast/slow verdict, and sig 132 is never standalone, so an absent Windows
 * arm cannot produce a false positive.
 * ------------------------------------------------------------------------- */
extern "C" void hk_dma_win_fill_tlp_latency(hk_dma_device_forensics *d) {
    if (d == nullptr) return;
    d->tlp_latency_median_ns = 0u;
    d->tlp_latency_iqr_ns = 0u;
    d->tlp_same_root_port_group = d->bdf.bus; /* coarse cohort key still useful. */
}
