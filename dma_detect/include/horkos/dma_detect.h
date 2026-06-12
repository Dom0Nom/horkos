/*
 * Role: Pure C interface for DMA-attack detection.
 *       Reports IOMMU state and suspicious DMA-capable PCIe devices to the
 *       caller; never makes a ban decision.  Cross-check logic (firmware claim
 *       vs. PCIe enumeration) is documented in docs/dma-detection.md.
 * Target platforms: Windows, Linux (macOS: no sysfs equivalent; stub only).
 * Interface declares: hk_dma_scan().
 *
 * NO platform headers are included here.  All OS-specific code lives in
 * dma_detect/backends/win/ and dma_detect/backends/linux/ (guardrail #1).
 */

#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* -------------------------------------------------------------------------
 * hk_dma_report
 *
 * Populated by hk_dma_scan().  All fields are unsigned to avoid sign-
 * extension accidents when the caller serialises to the event wire format.
 *
 * iommu_enabled
 *   1  — IOMMU/VT-d is active according to firmware (DMAR table on x86,
 *         SMMU table on ARM64).  This is the firmware's self-report and MAY
 *         be false — see high_confidence_flag and docs/dma-detection.md.
 *   0  — Firmware reports IOMMU absent or disabled.
 *
 * iommu_groups_present
 *   Count of distinct IOMMU groups visible through the OS kernel.  A non-
 *   zero count is positive corroboration that IOMMU is active; zero when
 *   iommu_enabled==1 is a firmware-vs-kernel disagreement and sets
 *   high_confidence_flag.
 *
 * suspicious_device_count
 *   Number of PCIe devices whose class / capability combination suggests
 *   the potential to perform peer-to-peer DMA without driver mediation
 *   (e.g. Bus Master Enable set, unknown/unbound vendor, DMA-engine class).
 *
 * high_confidence_flag
 *   Set to 1 when the scan has affirmative evidence of a concerning state
 *   beyond a single firmware claim:
 *     - Firmware says IOMMU on, but iommu_groups_present == 0.
 *     - Suspicious devices present AND iommu is not corroborated by the OS.
 *     - Any bus-master-capable device with no bound kernel driver.
 *   The server — not this library — decides what to do with this flag.
 *
 * scan_error
 *   Non-zero if the scan could not complete (permission denied, sysfs
 *   unavailable, SetupAPI failure, etc.).  On error the other fields are
 *   zero-initialised and must not be trusted.
 * ------------------------------------------------------------------------- */
typedef struct hk_dma_report {
    uint8_t  iommu_enabled;           /* Firmware / ACPI claim: 0 or 1.        */
    uint8_t  high_confidence_flag;    /* Cross-check mismatch detected: 0 or 1.*/
    uint8_t  _pad[2];                 /* Explicit padding; must be zero.        */
    uint32_t iommu_groups_present;    /* Kernel-visible IOMMU groups (Linux) or
                                         DMAR remapping units (Windows).        */
    uint32_t suspicious_device_count; /* DMA-capable suspect devices found.     */
    uint32_t scan_error;              /* 0 = success; non-zero = errno/HRESULT. */
} hk_dma_report;

/* -------------------------------------------------------------------------
 * hk_dma_scan
 *
 * Enumerates PCIe devices and queries IOMMU state via OS APIs.  Populates
 * *out and returns 0 on success, -1 on fatal error (out->scan_error set).
 *
 * Thread-safety: not re-entrant; caller must serialise if needed.
 * Side effects:  read-only; no kernel state is modified.
 * Latency:       O(device count), typically < 50 ms on desktop hardware.
 * ------------------------------------------------------------------------- */
int hk_dma_scan(hk_dma_report *out);

#ifdef __cplusplus
} /* extern "C" */
#endif
