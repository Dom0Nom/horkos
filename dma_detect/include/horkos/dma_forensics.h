/*
 * dma_detect/include/horkos/dma_forensics.h
 * Role: Pure-C struct/report interface for the nine PCIe device-forensic
 *       signals (catalog 127-135): DSN forgery, ext-config stability, MSI-X
 *       containment, option-ROM identity, BAR geometry, TLP latency, ACS/IOMMU
 *       topology, hot-plug arrival, and IOMMU-fault counts. Models per-device
 *       structural facts only — every probe is a read or an event subscription;
 *       NO scoring and NO ban decision happen here (those are server-side).
 *       This is an ADDITIVE sibling to hk_dma_report (dma_detect.h), which is
 *       unchanged.
 * Target platforms: Windows, Linux, macOS (each backend in
 *       dma_detect/backends/{win,linux,macos}/; this header is platform-clean).
 * Interface declares: hk_dma_forensics_scan, hk_dma_forensics_subscribe,
 *       hk_dma_forensics_unsubscribe.
 *
 * NO platform headers are included here (guardrail #1). All OS-specific code
 * lives under dma_detect/backends/<os>/, selected by CMake.
 */

#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* -------------------------------------------------------------------------
 * hk_pci_bdf — PCIe routing id. 4 bytes, no padding.
 * devfn packs (device << 3) | function, matching the kernel's PCI_DEVFN.
 * ------------------------------------------------------------------------- */
typedef struct hk_pci_bdf {
    uint16_t domain;
    uint8_t  bus;
    uint8_t  devfn;                    /* (dev << 3) | func */
} hk_pci_bdf;

/* -------------------------------------------------------------------------
 * hk_dma_device_forensics — one record per enumerated PCIe device.
 *
 * All fields unsigned/fixed-width (mirrors the hk_dma_report discipline so the
 * server-side serde mirror is a 1:1 field map). Boolean facts are 0/1 uint8_t;
 * a value the backend could NOT determine stays 0 (its absence carries no
 * verdict — the server gates on conjunctions of positive facts only).
 *
 * The structural-gate fields (bus_master_enabled, driver_bound) are populated
 * by the platform backend; the aggregator (forensics_report.cpp) reads them to
 * decide which devices the server should even score (an unbound + bus-master
 * device is the catalog's structural pre-requisite for most signals).
 * ------------------------------------------------------------------------- */
typedef struct hk_dma_device_forensics {
    hk_pci_bdf bdf;
    uint16_t   vendor_id;
    uint16_t   device_id;
    uint16_t   subsys_vendor_id;

    /* --- sig 127 (DSN forgery) / 128 (ext-config stability) --- */
    uint8_t    dsn_present;             /* DSN ext-cap (0x0003) found.            */
    uint8_t    dsn_oui_matches_vendor;  /* EUI-64 OUI consistent with VID (1=yes).*/
    uint8_t    extcfg_aliases_low;      /* 0x100-0x1FF mirrors 0x000-0x0FF.       */
    uint8_t    rsvdp_nonzero;           /* An RsvdP invariant byte was non-zero.  */
    uint8_t    extcfg_read_unstable;    /* Repeated reads not byte-identical.     */

    /* --- sig 129 (MSI-X containment) --- */
    uint8_t    msix_containment_violation;
    uint16_t   msix_table_size;         /* Table Size field + 1 (entry count).    */

    /* --- sig 130 (option ROM identity) --- */
    uint8_t    rom_present;
    uint8_t    rom_pcir_id_mismatch;    /* PCIR VID/DID != config VID/DID.        */

    /* --- sig 131 (BAR geometry) --- */
    uint8_t    bar_profile_count;       /* Count of decoded BARs in bar_size[].   */
    uint8_t    _pad0;                   /* Explicit; must be zero.                */
    uint64_t   bar_size[6];             /* Decoded length per BAR (0 = unused).   */
    uint8_t    bar_flags[6];            /* bit0=64-bit, bit1=prefetch, bit2=io.   */
    uint8_t    _pad1[2];                /* Explicit; must be zero.                */

    /* --- sig 133 (ACS / IOMMU-group topology) --- */
    uint8_t    acs_source_validation;   /* ACS SV control bit on the path bridge. */
    uint8_t    acs_p2p_redirect;        /* ACS P2P-Request-Redirect control bit.  */
    uint8_t    _pad2[2];                /* Explicit; must be zero.                */
    uint32_t   iommu_group_membership;  /* Device count in this device's group.   */

    /* --- structural gates (set by the platform backend / aggregator) --- */
    uint8_t    bus_master_enabled;      /* PCI_COMMAND bit 2 (Bus Master Enable). */
    uint8_t    driver_bound;            /* A kernel driver owns this device.      */
    uint8_t    _pad3[2];                /* Explicit; must be zero.                */

    /* --- sig 132 (TLP latency side-channel — LOW WEIGHT) --- */
    uint32_t   tlp_latency_median_ns;
    uint32_t   tlp_latency_iqr_ns;
    uint8_t    tlp_same_root_port_group;/* Peer-cohort id (same root port).       */
    uint8_t    _pad4[3];                /* Explicit; must be zero.                */

    /* --- sig 135 (IOMMU faults) --- */
    /* Populated on Linux by the eBPF iommu_fault counter merged in by the
     * loader, or on Windows by the ETW consumer; 0 when the source is absent
     * (the server must treat absence as "unknown", never "clean"). */
    uint32_t   iommu_fault_count;

    /* Per-device scan error (errno/HRESULT/IOReturn); 0 = this record is
     * trustworthy. A non-zero value means some fields could not be sampled and
     * the server must not read positive facts off this record as ground truth. */
    uint32_t   scan_error;
} hk_dma_device_forensics;

/* -------------------------------------------------------------------------
 * hk_dma_forensics_scan
 *
 * Enumerates PCIe devices and fills *out with up to *inout_count records.
 * On entry *inout_count is the capacity of the out array; on return it is the
 * number of records written. Returns 0 on success, -1 on fatal error (no
 * device was enumerable). A per-device failure sets that record's scan_error
 * and does NOT fail the whole scan.
 *
 * Thread-safety: not re-entrant; caller serialises.
 * Side effects:  read-only EXCEPT the sig-130 option-ROM probe, which briefly
 *                enables ROM decode and restores it (skipped when a driver owns
 *                the ROM region — see OptionRomForensics).
 * ------------------------------------------------------------------------- */
int hk_dma_forensics_scan(hk_dma_device_forensics *out, uint32_t *inout_count);

/* -------------------------------------------------------------------------
 * hk_dma_forensics_subscribe (sig 134 — live hot-plug arrival)
 *
 * Registers a callback invoked on each PCIe device arrival, with the arriving
 * BDF and a monotonic nanosecond timestamp. Returns 0 and writes an opaque
 * handle to *out_handle on success, -1 on failure. Subscribe, do NOT poll.
 *
 * The callback runs on a backend-owned monitor thread; it must be cheap and
 * non-blocking. This is a matching/notification path, NOT an ES auth event —
 * guardrail #7 (ES auth-reply deadline) does not apply here.
 * ------------------------------------------------------------------------- */
typedef void (*hk_dma_arrival_cb)(const hk_pci_bdf *bdf, uint64_t mono_ns, void *ctx);
int  hk_dma_forensics_subscribe(hk_dma_arrival_cb cb, void *ctx, void **out_handle);
void hk_dma_forensics_unsubscribe(void *handle);

#ifdef __cplusplus
} /* extern "C" */
#endif
