/*
 * sdk/include/horkos/event_schema.h
 * Role: Wire-format source of truth for all Horkos events.
 *       Phase 2 Rust serde structs mirror these field names and sizes.
 *       Phase 3 IOCTL header includes this file directly.
 *       Any field addition bumps HK_EVENT_SCHEMA_VERSION; no field renames;
 *       deprecated fields stay as reserved padding (see docs/event-schema.md).
 * Target platforms: all (plain C99, no platform headers, no compiler extensions).
 * Interface: included by both kernel TUs and userspace TUs — never in the same
 *            translation unit (guardrail #4).
 */

#pragma once

#include <stdint.h>

/* -------------------------------------------------------------------------
 * HK_STATIC_ASSERT — portable compile-time assert.
 * Bare `static_assert` is C++/C11 only; an MSVC kernel C build targeting an
 * older C dialect rejects it, which would break the kernel build before any
 * driver code compiles. Pick the strongest form the current dialect supports
 * and fall back to the negative-array typedef trick on plain C99.
 * ------------------------------------------------------------------------- */
#if defined(__cplusplus)
#  define HK_STATIC_ASSERT(cond, msg) static_assert(cond, msg)
#elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
#  define HK_STATIC_ASSERT(cond, msg) _Static_assert(cond, msg)
#else
#  define HK_SA_CAT_(a, b) a##b
#  define HK_SA_CAT(a, b) HK_SA_CAT_(a, b)
/* Keyed on __COUNTER__ (not __LINE__) so two asserts at the same line in
 * different headers within one TU cannot collide into a duplicate typedef. */
#  define HK_STATIC_ASSERT(cond, msg) \
      typedef char HK_SA_CAT(hk_static_assert_, __COUNTER__)[(cond) ? 1 : -1]
#endif

/* Schema version. Bumped on every additive field change. Mirrored by the
 * Phase 2 server in lockstep. v2 added hk_event_process_exit and the image
 * flags field. v3 added the memory/image-anomaly event family (types 5..13),
 * which rides a separate large-record wire plane (see ioctl.h
 * hk_event_mem_record) — the 16-byte hk_event_record plane is unchanged. v4
 * added the hypervisor/virtualization kernel-event family (types 14..17), four
 * compact 16-byte payloads that ride the existing hk_event_record ring; the
 * bulky raw HV vectors/histograms ride the usermode JSON report plane instead. */
#define HK_EVENT_SCHEMA_VERSION 4u

/* -------------------------------------------------------------------------
 * Event type enumeration.
 * New types are appended; existing values never change.
 * ------------------------------------------------------------------------- */
typedef enum hk_event_type {
    HK_EVENT_UNKNOWN         = 0,
    HK_EVENT_PROCESS_CREATE  = 1,
    HK_EVENT_PROCESS_EXIT    = 2,
    HK_EVENT_IMAGE_LOAD      = 3,
    HK_EVENT_HANDLE_OPEN     = 4,
    /* Memory & image-anomaly family (schema v3). These ride the large-record
     * wire plane (ioctl.h hk_event_mem_record), not the 16-byte hk_event_record
     * ring. The kernel scan worker emits raw evidence; the server classifies. */
    HK_EVENT_MEM_UNBACKED_EXEC    = 5,  /* signal 10: executable VAD, no backing. */
    HK_EVENT_MEM_WX_DIVERGENCE    = 6,  /* signal 11: PTE NX vs VAD protection. */
    HK_EVENT_MEM_MODULE_STOMP     = 7,  /* signal 12: on-disk vs in-memory .text. */
    HK_EVENT_MEM_GHOST_IMAGE      = 8,  /* signal 13: image VAD absent from Ldr. */
    HK_EVENT_MEM_PRIV_EXEC_COMMIT = 9,  /* signal 14: oversized private +X commit. */
    HK_EVENT_MEM_EXOTIC_VAD       = 10, /* signal 15: large-page / VAD-rotate +X. */
    HK_EVENT_MEM_HOLLOW_BACKING   = 11, /* signal 16: backing name/state mismatch. */
    HK_EVENT_MEM_EXEC_ORIGIN_ANON = 12, /* signal 17: thread/TLS origin unbacked. */
    HK_EVENT_MEM_UNSIGNED_IMAGE   = 13, /* signal 18: backing lacks signing prov. */
    /* Hypervisor/virtualization family (schema v4). Four compact 16-byte kernel
     * records on the existing hk_event_record ring; the bulky raw HV data rides
     * the usermode JSON report plane (hv_signals.h). Kernel emits raw evidence;
     * the server classifies (population modeling, per-SKU baselines). */
    HK_EVENT_HV_SYNTH_MSR   = 14, /* signal 42: Hyper-V synthetic MSR coherence. */
    HK_EVENT_HV_EPT_SPLIT   = 15, /* signal 39: EPT exec/read view split. */
    HK_EVENT_HV_SK_LIVENESS = 16, /* signal 41: secure-kernel liveness (observe). */
    HK_EVENT_HV_APIC_IDT    = 17, /* signal 44: APIC/IDT virtualization residue. */
} hk_event_type;

/* -------------------------------------------------------------------------
 * Normalized constants for the memory/image-anomaly family. The kernel scan
 * worker reduces build-specific MMVAD/PTE state into these stable values
 * before they cross the wire, so the server never sees a raw kernel layout.
 * ------------------------------------------------------------------------- */

/* Normalized VadType (independent of the build-specific MMVAD enum). */
#define HK_MEM_VAD_NONE        0u  /* private (VadNone) — no section backing. */
#define HK_MEM_VAD_IMAGE       1u  /* image-backed mapping. */
#define HK_MEM_VAD_AWE         2u  /* Address Windowing Extensions region. */
#define HK_MEM_VAD_ROTATE      3u  /* rotate-physical region. */
#define HK_MEM_VAD_LARGE_PAGES 4u  /* large-page region. */
#define HK_MEM_VAD_OTHER       5u

/* Normalized protection bits (independent of MM_EXECUTE* build constants). */
#define HK_MEM_PROT_READ    0x1u
#define HK_MEM_PROT_WRITE   0x2u
#define HK_MEM_PROT_EXECUTE 0x4u

/* hk_mem_region.flags bits (signals 10/14/15). */
#define HK_MEM_REGION_FLAG_UNBACKED      0x1u /* no ControlArea/FilePointer. */
#define HK_MEM_REGION_FLAG_LARGE_PAGE    0x2u
#define HK_MEM_REGION_FLAG_HAS_JIT_OWNER 0x4u /* inside a known-JIT module range. */

/* hk_event_mem_image_anomaly.flags bits (signals 13 ghost + 16 hollow). */
#define HK_MEM_IMG_FLAG_GHOST          0x01u /* image VAD in none of the Ldr lists. */
#define HK_MEM_IMG_FLAG_HOLLOW         0x02u /* hollow/doppelgang backing. */
#define HK_MEM_IMG_FLAG_DELETE_PENDING 0x04u
#define HK_MEM_IMG_FLAG_TRANSACTED     0x08u
#define HK_MEM_IMG_FLAG_NAME_MISMATCH  0x10u /* FILE_OBJECT name != Ldr path. */
#define HK_MEM_IMG_FLAG_ENTRY_REGION   0x20u /* region contains the entry point. */
#define HK_MEM_IMG_FLAG_EXEC           0x40u
#define HK_MEM_IMG_FLAG_HAS_JIT_OWNER  0x80u

/* hk_event_mem_exec_origin.flags bits (signal 17). */
#define HK_MEM_ORIGIN_FLAG_ANON         0x1u /* resolved into an unbacked region. */
#define HK_MEM_ORIGIN_FLAG_TLS_CALLBACK 0x2u /* origin is a TLS callback (not thread). */
#define HK_MEM_ORIGIN_FLAG_HAS_JIT_OWNER 0x4u

/* signer_verdict enum (signal 18). The kernel ships HK_SIGN_UNKNOWN; userspace
 * (ImageSigningWin.cpp via WinVerifyTrust) overwrites it before forwarding. */
#define HK_SIGN_UNKNOWN   0u
#define HK_SIGN_UNSIGNED  1u
#define HK_SIGN_SELF      2u
#define HK_SIGN_UNTRUSTED 3u
#define HK_SIGN_TRUSTED   4u

/* -------------------------------------------------------------------------
 * Payload: common region descriptor — reused by signals 10, 14, 15
 * (HK_EVENT_MEM_UNBACKED_EXEC / _PRIV_EXEC_COMMIT / _EXOTIC_VAD).
 * Fixed size: 32 bytes.
 * ------------------------------------------------------------------------- */
typedef struct hk_mem_region {
    uint32_t pid;
    uint32_t vad_type;     /* HK_MEM_VAD_*. */
    uint64_t region_base;  /* StartingVpn << PAGE_SHIFT. */
    uint64_t region_size;  /* (EndingVpn - StartingVpn + 1) << PAGE_SHIFT. */
    uint32_t protection;   /* HK_MEM_PROT_* mask. */
    uint32_t flags;        /* HK_MEM_REGION_FLAG_*. */
} hk_mem_region;

HK_STATIC_ASSERT(sizeof(hk_mem_region) == 32, "hk_mem_region wire size drift");

/* -------------------------------------------------------------------------
 * Payload: HK_EVENT_MEM_WX_DIVERGENCE (signal 11). Fixed size: 40 bytes.
 * ------------------------------------------------------------------------- */
typedef struct hk_event_mem_wx {
    hk_mem_region region;     /* 32 */
    uint32_t      vad_says_exec; /* 0/1 from VAD protection. */
    uint32_t      pte_says_exec; /* 0/1 from live leaf-PTE NX bit. */
} hk_event_mem_wx;

HK_STATIC_ASSERT(sizeof(hk_event_mem_wx) == 40, "hk_event_mem_wx wire size drift");

/* -------------------------------------------------------------------------
 * Payload: HK_EVENT_MEM_MODULE_STOMP (signal 12). Largest payload — pins
 * HK_EVENT_MEM_PAYLOAD_MAX in ioctl.h. Fixed size: 304 bytes.
 * ------------------------------------------------------------------------- */
typedef struct hk_event_mem_module_stomp {
    uint32_t pid;
    uint32_t first_diff_rva;          /* RVA of first unexplained code byte. */
    uint64_t image_base;
    uint8_t  live_section_sha256[32];
    uint8_t  disk_section_sha256[32];
    uint16_t module_path_len;         /* bytes used in module_path (<= 208). */
    uint16_t section_name_len;        /* bytes used in section_name (<= 8). */
    uint8_t  module_path[208];        /* UTF-16 -> UTF-8 path, truncated. */
    uint8_t  section_name[8];         /* e.g. ".text". */
} hk_event_mem_module_stomp;

HK_STATIC_ASSERT(sizeof(hk_event_mem_module_stomp) == 304,
    "hk_event_mem_module_stomp wire size drift");

/* -------------------------------------------------------------------------
 * Payload: HK_EVENT_MEM_GHOST_IMAGE (13) + HK_EVENT_MEM_HOLLOW_BACKING (16)
 * share this {pid, flags, base, path} shape; the server demuxes on header.type
 * and reads HK_MEM_IMG_FLAG_* to tell ghost from hollow + backing state.
 * Fixed size: 232 bytes.
 * ------------------------------------------------------------------------- */
typedef struct hk_event_mem_image_anomaly {
    uint32_t pid;
    uint32_t flags;        /* HK_MEM_IMG_FLAG_*. */
    uint64_t image_base;
    uint16_t path_len;     /* bytes used in path (<= 208). */
    uint16_t reserved;     /* must be zero. */
    uint8_t  path[208];    /* Ldr-recorded path, UTF-16 -> UTF-8, truncated. */
} hk_event_mem_image_anomaly;

HK_STATIC_ASSERT(sizeof(hk_event_mem_image_anomaly) == 232,
    "hk_event_mem_image_anomaly wire size drift");

/* -------------------------------------------------------------------------
 * Payload: HK_EVENT_MEM_EXEC_ORIGIN_ANON (signal 17). Fixed size: 24 bytes.
 * ------------------------------------------------------------------------- */
typedef struct hk_event_mem_exec_origin {
    uint32_t pid;
    uint32_t thread_id;        /* TID whose start address resolved anon (0 = TLS). */
    uint64_t start_address;    /* Win32 start address or TLS callback target. */
    uint32_t resolved_vad_type;/* HK_MEM_VAD_* the target resolved into. */
    uint32_t flags;            /* HK_MEM_ORIGIN_FLAG_*. */
} hk_event_mem_exec_origin;

HK_STATIC_ASSERT(sizeof(hk_event_mem_exec_origin) == 24,
    "hk_event_mem_exec_origin wire size drift");

/* -------------------------------------------------------------------------
 * Payload: HK_EVENT_MEM_UNSIGNED_IMAGE (signal 18). Kernel ships path + hash
 * with signer_verdict = HK_SIGN_UNKNOWN; userspace fills the verdict.
 * Fixed size: 264 bytes.
 * ------------------------------------------------------------------------- */
typedef struct hk_event_mem_unsigned_image {
    uint32_t pid;
    uint32_t signer_verdict;   /* HK_SIGN_* (kernel: UNKNOWN; userspace fills). */
    uint64_t image_base;
    uint8_t  file_sha256[32];
    uint16_t path_len;         /* bytes used in file_path (<= 208). */
    uint16_t reserved;         /* must be zero. */
    uint8_t  file_path[208];
} hk_event_mem_unsigned_image;

HK_STATIC_ASSERT(sizeof(hk_event_mem_unsigned_image) == 264,
    "hk_event_mem_unsigned_image wire size drift");

/* -------------------------------------------------------------------------
 * Hypervisor/virtualization kernel-event family (schema v4). Each payload is
 * pinned at 16 bytes so it rides the existing 16-byte hk_event_record ring with
 * no change to HK_EVENT_PAYLOAD_MAX or hk_event_record. The kernel ships only a
 * compact verdict-input summary + correlation flags; the bulky raw leaf
 * vectors / latency histograms ride the usermode JSON report plane.
 * ------------------------------------------------------------------------- */

/* hk_event_hv_synth_msr.flags bits (signal 42). */
#define HK_HV_MSR_CPUID_CLAIMS_HV 0x1u /* CPUID leaf 0x40000000 claims a hypervisor. */
#define HK_HV_MSR_GUEST_OS_ID_OK  0x2u /* HV_X64_MSR_GUEST_OS_ID readable + nonzero. */
#define HK_HV_MSR_HYPERCALL_OK    0x4u /* HV_X64_MSR_HYPERCALL readable. */
#define HK_HV_MSR_REF_TSC_COHERENT 0x8u /* reference-TSC vs rdtsc within tolerance. */
#define HK_HV_MSR_GP_FAULTED      0x10u /* at least one synthetic MSR read #GP'd. */

/* Payload: HK_EVENT_HV_SYNTH_MSR (signal 42). 16 bytes. */
typedef struct hk_event_hv_synth_msr {
    uint32_t flags;            /* HK_HV_MSR_*. */
    uint32_t gp_fault_mask;    /* bit per synthetic MSR whose read #GP'd. */
    uint64_t ref_tsc_vs_rdtsc; /* signed reference-TSC vs rdtsc skew sample, ns. */
} hk_event_hv_synth_msr;

HK_STATIC_ASSERT(sizeof(hk_event_hv_synth_msr) == 16,
    "hk_event_hv_synth_msr wire size drift");

/* hk_event_hv_ept_split.flags bits (signal 39). */
#define HK_HV_EPT_SPLIT_DETECTED 0x1u /* exec-view checksum != read-view checksum. */
#define HK_HV_EPT_HVCI_MANAGED   0x2u /* region is an HVCI-managed range (FP gate). */
#define HK_HV_EPT_VE_ARMED       0x4u /* #VE expectation was armed for this section. */

/* Payload: HK_EVENT_HV_EPT_SPLIT (signal 39). 16 bytes. */
typedef struct hk_event_hv_ept_split {
    uint32_t exec_view_crc; /* checksum of the section read through the exec view. */
    uint32_t read_view_crc; /* checksum of the section read through the data view. */
    uint32_t flags;         /* HK_HV_EPT_*. */
    uint32_t section_id;    /* which signed section this sample covers. */
} hk_event_hv_ept_split;

HK_STATIC_ASSERT(sizeof(hk_event_hv_ept_split) == 16,
    "hk_event_hv_ept_split wire size drift");

/* hk_event_hv_sk_liveness.flags bits (signal 41, observe-only). */
#define HK_HV_SK_IUM_RUNNING     0x1u /* isolated-user-mode reports running. */
#define HK_HV_SK_IMAGE_LOADED    0x2u /* securekernel.exe/skci.dll seen loaded. */

/* Payload: HK_EVENT_HV_SK_LIVENESS (signal 41). 16 bytes. */
typedef struct hk_event_hv_sk_liveness {
    uint32_t flags;                  /* HK_HV_SK_*. */
    uint32_t transition_count_bucket;/* bucketed secure-kernel transition count. */
    uint64_t reserved;               /* must be zero. */
} hk_event_hv_sk_liveness;

HK_STATIC_ASSERT(sizeof(hk_event_hv_sk_liveness) == 16,
    "hk_event_hv_sk_liveness wire size drift");

/* hk_event_hv_apic_idt.flags bits (signal 44, observe-only). */
#define HK_HV_APIC_IDT_MISMATCH  0x1u /* __sidt base != KPCR-authoritative IDT base. */

/* Payload: HK_EVENT_HV_APIC_IDT (signal 44). 16 bytes. */
typedef struct hk_event_hv_apic_idt {
    uint32_t sidt_base_low;     /* low 32 bits of the __sidt-reported IDT base. */
    uint32_t kpcr_idt_base_low; /* low 32 bits of the KPCR-authoritative IDT base. */
    uint32_t flags;             /* HK_HV_APIC_IDT_*. */
    uint32_t apic_exit_bucket;  /* bucketed local-APIC access-exit timing. */
} hk_event_hv_apic_idt;

HK_STATIC_ASSERT(sizeof(hk_event_hv_apic_idt) == 16,
    "hk_event_hv_apic_idt wire size drift");

/* -------------------------------------------------------------------------
 * Common event header — present at the start of every event payload.
 * Fixed size: 24 bytes. Verified by HK_STATIC_ASSERT below.
 * ------------------------------------------------------------------------- */
typedef struct hk_event_header {
    uint32_t version;        /* HK_EVENT_SCHEMA_VERSION at emit time. */
    uint32_t type;           /* One of hk_event_type. */
    uint64_t timestamp_ns;   /* Monotonic ns (boot/interrupt epoch) at emit. */
    uint32_t payload_bytes;  /* Size of the payload struct that follows. */
    uint32_t reserved;       /* Padding to 24 bytes; must be zero. */
} hk_event_header;

HK_STATIC_ASSERT(sizeof(hk_event_header) == 24,
    "hk_event_header size mismatch — update the kernel-event serde mirror when "
    "it lands (not yet present in server/)");

/* -------------------------------------------------------------------------
 * Payload: HK_EVENT_PROCESS_CREATE
 * Fixed size: 16 bytes.
 * ------------------------------------------------------------------------- */
typedef struct hk_event_process_create {
    uint32_t pid;            /* New process PID. */
    uint32_t parent_pid;     /* Parent process PID. */
    uint64_t create_time_ns; /* Process creation time, 1601/FILETIME epoch ns.
                                NOTE: different epoch from header.timestamp_ns;
                                the server must not compare the two directly. */
} hk_event_process_create;

HK_STATIC_ASSERT(sizeof(hk_event_process_create) == 16,
    "hk_event_process_create size mismatch");

/* -------------------------------------------------------------------------
 * Payload: HK_EVENT_PROCESS_EXIT
 * Fixed size: 16 bytes. Added in schema v2.
 * ------------------------------------------------------------------------- */
typedef struct hk_event_process_exit {
    uint32_t pid;            /* Exiting process PID. */
    uint32_t reserved;       /* Padding; must be zero. */
    uint64_t exit_time_ns;   /* Exit time, monotonic ns (boot/interrupt epoch). */
} hk_event_process_exit;

HK_STATIC_ASSERT(sizeof(hk_event_process_exit) == 16,
    "hk_event_process_exit size mismatch");

/* -------------------------------------------------------------------------
 * Payload: HK_EVENT_IMAGE_LOAD
 * Fixed size: 16 bytes. The former 'reserved' word became 'flags' in v2
 * (size unchanged; old readers saw zero there, which is HK_IMAGE_FLAG none).
 * ------------------------------------------------------------------------- */
typedef struct hk_event_image_load {
    uint32_t pid;            /* PID of the loading process. */
    uint32_t flags;          /* HK_IMAGE_FLAG_* bitmask (0 = normal load). */
    uint64_t image_base;     /* Virtual base address where the image was mapped. */
} hk_event_image_load;

HK_STATIC_ASSERT(sizeof(hk_event_image_load) == 16,
    "hk_event_image_load size mismatch");

/* Image-load flags. */
#define HK_IMAGE_FLAG_BYOVD_SUSPECT 0x00000001u

/* -------------------------------------------------------------------------
 * Payload: HK_EVENT_HANDLE_OPEN
 * Fixed size: 16 bytes.
 * ------------------------------------------------------------------------- */
typedef struct hk_event_handle_open {
    uint32_t requesting_pid; /* PID that opened the handle. */
    uint32_t target_pid;     /* PID of the process whose handle was opened. */
    uint32_t access_mask;    /* OriginalDesiredAccess the requester asked for. */
    uint32_t reserved;       /* Padding; must be zero. */
} hk_event_handle_open;

HK_STATIC_ASSERT(sizeof(hk_event_handle_open) == 16,
    "hk_event_handle_open size mismatch");
