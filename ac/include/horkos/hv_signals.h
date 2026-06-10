/*
 * ac/include/horkos/hv_signals.h
 * Role: Usermode hypervisor/virtualization-state sensor surface. One fixed POD
 *       result struct + sampler per signal (37 TLFS leaves, 38 vmexit latency,
 *       40 VBS attestation, 43 VM identity, 45 TSC coherence), a kernel-record
 *       summary folded from the ring (signals 39/41/42/44), and an
 *       `hv_collect_all()` aggregator. Each sampler reports RAW vectors /
 *       histograms / tuples; there is deliberately no verdict field — all
 *       classification (population modeling, per-SKU skew, known-good nested-
 *       Hyper-V vectors) is server-side. The pure structural-consistency cores
 *       that turn these raw fields into observations live in hv_logic.h and are
 *       host-tested; the platform sampling that fills them lives in
 *       ac/src/hv/*.cpp (Windows) and is not part of this header.
 *       READ-ONLY: samples processor/OS state; mutates nothing.
 * Target platforms: Windows (the samplers); the POD surface + hv_logic.h cores
 *       are host-compilable (plain C, no platform header here).
 * Interface: this header IS the HV sensor surface; ac/src/hv/*.cpp implement the
 *       samplers; consumed by ac/src/ac.cpp. Status codes reuse HK_AC_* from
 *       horkos/ac.h (a sampler unavailable on the current platform returns
 *       HK_AC_NOT_IMPLEMENTED and clears its sensors_ok bit).
 */

#pragma once

#include <stdint.h>

#include "horkos/ac.h"

#ifdef __cplusplus
extern "C" {
#endif

/* hv_report.sensors_ok bits — which samplers ran cleanly this cycle. */
#define HK_HV_OK_TLFS     0x01u
#define HK_HV_OK_VMEXIT   0x02u
#define HK_HV_OK_VBS      0x04u
#define HK_HV_OK_IDENTITY 0x08u
#define HK_HV_OK_TSC      0x10u
#define HK_HV_OK_KERNEL   0x20u

/* Signal 43 raw classification (the client ships the structural class; the
 * server makes the trust decision against attested-fleet allowlists). */
#define HK_HV_VMID_UNKNOWN           0u
#define HK_HV_VMID_BARE_METAL        1u
#define HK_HV_VMID_HONEST_VM         2u
#define HK_HV_VMID_COVERT_INSPECTION 3u

/* Signal 37 — TLFS hypervisor CPUID leaves + OS posture. */
typedef struct hv_tlfs_leaves {
    uint32_t leaf[11][4];     /* CPUID 0x40000000..0x4000000A, EAX/EBX/ECX/EDX. */
    uint32_t cpuid1_ecx31_hv; /* leaf 1 ECX[31] hypervisor-present bit. */
    uint32_t os_vbs_running;  /* SystemIsolatedUserModeInformation. */
    uint32_t os_hv_present;   /* SystemHypervisorDetailInformation. */
    uint32_t reserved;
} hv_tlfs_leaves;

/* Signal 38 — vmexit (serialized-instruction) latency histogram. */
typedef struct hv_vmexit_latency {
    uint32_t hist[32];           /* CPUID round-trip latency buckets (cycles). */
    uint32_t cpu_model;          /* CPUID family/model/stepping. */
    uint64_t qpc_span;           /* independent QPC span over the loop. */
    uint64_t shared_interrupt_dt;/* KUSER_SHARED_DATA.InterruptTime delta. */
} hv_vmexit_latency;

/* Signal 40 — VBS/HVCI enablement vs attestation. */
typedef struct hv_vbs_attest {
    uint32_t vbs_status;          /* Win32_DeviceGuard VirtualizationBasedSecurityStatus. */
    uint32_t security_services;   /* SecurityServicesRunning bitmask. */
    uint32_t ci_policy;           /* CodeIntegrityPolicyEnforcementStatus. */
    uint32_t attest_quote_avail;  /* 1 if Attestation::quote() returned a quote. */
    uint32_t attest_contradiction;/* 1 if quote contradicts the WMI-claimed posture. */
    uint32_t reserved;
} hv_vbs_attest;

/* Signal 43 — sanctioned-VM identity vs covert inspection. */
typedef struct hv_vm_identity {
    uint32_t cpuid_hv_present;     /* leaf 1 ECX[31]. */
    uint32_t smbios_vm_marker;     /* SMBIOS vendor/product indicates a VM. */
    uint32_t devicetree_vm_marker; /* device-tree IDs indicate a VM. */
    uint32_t vtpm_ek_present;      /* vTPM EK retrievable. */
    uint32_t classification;       /* HK_HV_VMID_* (raw structural class). */
    uint32_t reserved;
} hv_vm_identity;

/* Signal 45 — cross-vCPU TSC coherence. */
typedef struct hv_tsc_coherence {
    uint32_t lp_count;          /* logical processors sampled. */
    uint32_t invariant_tsc;     /* CPUID 0x80000007 EDX[8]. */
    uint64_t max_abs_skew;      /* max |skew| across LPs (raw; server baselines). */
    uint32_t monotonic;         /* 1 if every per-LP sample sequence was monotonic. */
    uint32_t aux_pin_verified;  /* 1 if IA32_TSC_AUX confirmed each affinity pin. */
} hv_tsc_coherence;

/* Kernel-record summary folded from the ring (signals 39/41/42/44). */
typedef struct hv_kernel_summary {
    uint32_t synth_msr_flags;    /* HK_HV_MSR_* from hk_event_hv_synth_msr. */
    uint32_t ept_flags;          /* HK_HV_EPT_* from hk_event_hv_ept_split. */
    uint32_t sk_flags;           /* HK_HV_SK_* from hk_event_hv_sk_liveness. */
    uint32_t apic_idt_flags;     /* HK_HV_APIC_IDT_* from hk_event_hv_apic_idt. */
    uint32_t records_seen;       /* count of kernel HV records folded this cycle. */
    uint32_t reserved;
} hv_kernel_summary;

/* Aggregate report uploaded to the server. */
typedef struct hv_report {
    hv_tlfs_leaves    tlfs;     /* 37 */
    hv_vmexit_latency vmexit;   /* 38 */
    hv_vbs_attest     vbs;      /* 40 */
    hv_vm_identity    identity; /* 43 */
    hv_tsc_coherence  tsc;      /* 45 */
    hv_kernel_summary kern;     /* 39/41/42/44 folded from the ring. */
    uint32_t          sensors_ok; /* HK_HV_OK_* bitmask. */
    uint32_t          reserved;
} hv_report;

/* Per-signal samplers (Windows; stub returns HK_AC_NOT_IMPLEMENTED elsewhere). */
int hv_sample_tlfs_leaves(hv_tlfs_leaves *out);
int hv_sample_vmexit_latency(hv_vmexit_latency *out);
int hv_sample_vbs_attest(hv_vbs_attest *out);
int hv_sample_vm_identity(hv_vm_identity *out);
int hv_sample_tsc_coherence(hv_tsc_coherence *out);

/* Drain + fold the kernel HV records (signals 39/41/42/44) into the summary. */
int hv_collect_kernel(hv_kernel_summary *out);

/* Run every available sampler + the kernel fold; build the report. */
int hv_collect_all(hv_report *out);

#ifdef __cplusplus
} /* extern "C" */
#endif
