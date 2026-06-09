/*
 * dma_detect/backends/win/IommuFaultEtw.cpp
 * Role: Windows IOMMU-fault (DMA-remapping fault) consumer (catalog signal 135,
 *       Windows arm). Intended to consume DMA-remapping fault events surfaced by a
 *       platform ETW provider (DeviceGuard / Microsoft-Windows-Kernel-* family) and
 *       count faults per source-BDF into hk_dma_device_forensics.iommu_fault_count,
 *       so the server can gate a steady fault stream on the faulting device also
 *       being a structural suspect. Read-only event subscription; no scoring/ban.
 * Target platforms: Windows only. Selected by CMake if(WIN32). Compiles into
 *       hk_dma_detect alongside the other win/ forensic backends.
 * Implements: the sig-135 hook of dma_detect/include/horkos/dma_forensics.h
 *       (merges iommu_fault_count; does NOT own hk_dma_forensics_scan — that lives
 *       in win/ConfigSpaceForensics.cpp, which may call into this arm).
 *
 * *** HK-UNCERTAIN(win-dmar-etw): the exact ETW PROVIDER GUID and EVENT ID for
 * DMA-remapping (IOMMU/DMAR) faults on Windows are NOT verified (impl-plan Risk #2),
 * and these events may not be surfaced at all on consumer SKUs. Per guardrail #13
 * this arm is therefore left UNIMPLEMENTED: it does NOT open a real-time ETW session
 * against a guessed provider GUID. The functions below are the consumer surface
 * (start/stop + per-BDF count merge) that the real session plugs into once the
 * provider GUID + event id are confirmed on-box; until then the consumer reports
 * "unavailable" and merges nothing, so the server treats sig-135 on Windows as
 * ABSENT (never "clean"). CONFIRM the provider GUID + event layout via a logman /
 * TraceLogging enumeration on the target SKU before wiring StartTrace/ProcessTrace.
 * ***
 */

#include <windows.h>
#include <cstdint>
#include <cstring>

#include "../../include/horkos/dma_forensics.h"

/* -------------------------------------------------------------------------
 * hk_dma_win_iommu_fault_available
 *
 * Returns 1 if a confirmed DMA-remapping-fault ETW provider is wired and a
 * real-time session can be opened on this host, else 0. It currently always
 * returns 0 (HK-UNCERTAIN(win-dmar-etw): no confirmed provider). Callers MUST
 * treat 0 as "sig-135 source absent" and leave iommu_fault_count at 0 with the
 * server informed (via the telemetry plane) that the source was unavailable — so
 * absence is never decoded as a clean device.
 * ------------------------------------------------------------------------- */
extern "C" int hk_dma_win_iommu_fault_available(void) {
    /* HK-UNCERTAIN(win-dmar-etw): no confirmed provider GUID/event id. Do not
     * open a session against a guessed GUID. Confirm on-box, then flip to 1 and
     * implement hk_dma_win_iommu_fault_start below. */
    return 0;
}

/* -------------------------------------------------------------------------
 * hk_dma_win_iommu_fault_start / _stop
 *
 * Consumer-session lifecycle stubs. start() returns a non-zero ERROR_* on the
 * uncertain path so the caller degrades to "absent"; stop() is a safe no-op when
 * no session was opened. The real bodies open a real-time ETW session against the
 * confirmed DMAR provider, register an EVENT_RECORD_CALLBACK that parses each
 * fault's source device into a packed BDF, and accumulate a per-BDF count that
 * hk_dma_win_iommu_fault_merge folds into the scan output.
 * ------------------------------------------------------------------------- */
extern "C" uint32_t hk_dma_win_iommu_fault_start(void **out_session) {
    if (out_session != nullptr) {
        *out_session = nullptr;
    }
    /* HK-UNCERTAIN(win-dmar-etw): no real-time session is opened. Return a
     * not-supported status so the caller marks sig-135 absent on this host. */
    return ERROR_NOT_SUPPORTED;
}

extern "C" void hk_dma_win_iommu_fault_stop(void *session) {
    /* No session is ever opened on the uncertain path; nothing to tear down.
     * When the real session lands, CloseTrace()/ControlTrace(EVENT_TRACE_CONTROL_STOP)
     * go here, on the thread that opened the session. */
    (void)session;
}

/* -------------------------------------------------------------------------
 * hk_dma_win_iommu_fault_merge
 *
 * Folds the per-BDF fault counts accumulated by an active consumer session into a
 * scan's device array (matching on packed BDF). On the uncertain path the session
 * is never active, so this is a no-op: every device keeps iommu_fault_count == 0,
 * which the server reads as "source absent", not "no faults observed".
 * ------------------------------------------------------------------------- */
extern "C" void hk_dma_win_iommu_fault_merge(void *session,
                                             hk_dma_device_forensics *devs,
                                             uint32_t count) {
    /* HK-UNCERTAIN(win-dmar-etw): no session, no counts to merge. */
    (void)session;
    (void)devs;
    (void)count;
}
