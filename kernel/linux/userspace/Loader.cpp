/*
 * kernel/linux/userspace/Loader.cpp
 * Role: libbpf userspace loader for the Horkos Linux eBPF programs.
 *       Opens both BPF skeletons (lsm_file_open + tracepoints), attaches all
 *       programs, then polls the shared ring buffer and translates each raw
 *       BPF event record into an hk_event_record (header + payload) before
 *       dispatching it to a caller-supplied sink callback.
 * Target platform: Linux userspace (glibc/musl).  Never compiled on Windows
 *                  or macOS (guardrail #4: pure userspace TU).
 * Interface: exports hk_bpf_loader_start() / hk_bpf_loader_stop() declared
 *            in Loader.h (same directory).
 *
 * API references:
 *   - libbpf docs:   https://libbpf.readthedocs.io/en/latest/api.html
 *   - ring_buffer:   https://libbpf.readthedocs.io/en/latest/api.html#ring-buffer
 *   - bpf_object:    https://libbpf.readthedocs.io/en/latest/api.html#bpf-object
 *
 * Guardrail compliance:
 *   #1  No raw platform macros — Linux-only by build gating (CMakeLists).
 *   #3  This module comment covers role/platform/interface.
 *   #4  Pure userspace TU: BPF-side structs are redeclared here rather than
 *       including BPF kernel headers.  Skeleton headers (.skel.h) generated
 *       by bpftool are userspace-safe (they include libbpf/bpf.h, not
 *       kernel/bpf.h).
 *   #8  N/A (C++ TU; async model is in the Rust server layer).
 */

#include "Loader.h"

/* Skeleton headers are generated into the cmake binary dir and added to the
 * include path by the hk_bpf_generated INTERFACE target. */
#include "lsm_file_open.skel.h"
#include "tracepoints.skel.h"

/* Memory-access sensor skeletons (signals 73-81). Built only when the
 * HORKOS_LINUX_EBPF_MEMORY feature flag is on (CMake defines HK_BPF_MEMORY_ACCESS
 * and adds bpf_program(...) for each). Guarded so the loader still compiles with
 * the memory set off. */
#ifdef HK_BPF_MEMORY_ACCESS
#include "lsm_ptrace.skel.h"
#include "fexit_process_vm.skel.h"
#include "fentry_proc_mem.skel.h"
#include "lsm_mmap_mprotect.skel.h"
#include "memfd_exec.skel.h"
#include "lsm_devmem.skel.h"
#include "iter_task_vma.skel.h"
#endif

/* libbpf userspace headers (libbpf-dev package on Debian/Ubuntu).
 * These are safe to include in userspace — they do not pull in kernel
 * internal headers.
 * Reference: https://libbpf.readthedocs.io/en/latest/api.html */
#include <bpf/libbpf.h>

/* Standard C++ / POSIX headers — permitted in userspace TUs. */
#include <cerrno>
#include <cstdarg>   /* va_list for libbpf_print_fn */
#include <cstdio>
#include <cstring>
#include <atomic>
#ifdef HK_BPF_MEMORY_ACCESS
#include <cstdint>
#include <unordered_map>   /* memfd<->exec (tgid,inode) correlation join map */
#include <unistd.h>        /* read() for the iter/task_vma seq stream */
#include "ProtectedSet.h"
#endif

#ifdef HK_BPF_PROTON_WINE
/* Proton/Wine/Deck verifier seams (signals 100-108). Each holds the userspace
 * allowlist/manifest/lineage logic and enriches the kernel-set flags before the
 * sink forwards the record; enrichment only sets REPORTED flags, never drops a
 * record (server adjudicates — guardrail: clients sample + report only). The
 * baseline data (manifests, allowlists, launcher PID lineage, session start) is
 * injected by the host-integrity aggregator; until that wiring lands the
 * classifiers run with empty baselines (report-only, no suppression). */
#include "ProtonOverrideCheck.h"
#include "PrefixMapAudit.h"
#include "ContainerNsBaseline.h"
#include "DeckModuleBaseline.h"
#include "DeckRootfsBaseline.h"
#include "GamescopeConsumerBaseline.h"
#include "WineBuiltinIntegrity.h"
#include "DeckInputBaseline.h"
#endif

/* horkos event schema (event_schema.h uses only stdint.h, no kernel headers).
 * Including it here is safe: it is explicitly documented as usable by both
 * kernel TUs and userspace TUs IN SEPARATE translation units (guardrail #4). */
#include <horkos/event_schema.h>

/* MsrPathResolver — userspace fd→device + MSR-index sensitivity resolution for
 * the signal-99 translate arm (§1.2 / §7-A: BPF emits raw fd/offset, userspace
 * resolves). Pure userspace header; safe to include in this TU. */
#include "MsrPathResolver.h"

/* ---- BPF-side event tags (mirrored from the .bpf.c files) ---------------- */
/*
 * These must stay in sync with the #defines in lsm_file_open.bpf.c and
 * tracepoints.bpf.c.  A mismatch silently drops or mis-tags events.
 */
static constexpr uint32_t kBpfTagFileOpen  = 0x10u;
static constexpr uint32_t kBpfTagPtrace    = 0x20u;
static constexpr uint32_t kBpfTagProcExec  = 0x21u;

/* Module-trust domain (signals 98/99) — extends the core lsm_file_open +
 * tracepoints programs, so these arms are ALWAYS compiled (not under
 * HK_BPF_MEMORY_ACCESS). The 0xA0 range avoids the memory-access tag values. */
static constexpr uint32_t kBpfTagDevmem    = 0xA0u;   /* lsm_file_open.bpf.c   */
static constexpr uint32_t kBpfTagMsrWrite  = 0xA1u;   /* tracepoints.bpf.c     */

/*
 * HK-TODO(schema): the module-trust event discriminants (HK_EVENT_DEVMEM_ACCESS
 * =12, HK_EVENT_MSR_WRITE_SENSITIVE=13) are owned by the Schema phase and are NOT
 * yet in the frozen event_schema.h. Mirrored here as provisional locals (same
 * pattern as the memory-access block). NOTE 12/13 collide pre-Schema with the
 * memory-access provisional values — Schema assigns the final distinct values.
 */
static constexpr uint32_t kEvtDevmemAccess      = 12u;
static constexpr uint32_t kEvtMsrWriteSensitive = 13u;

#ifdef HK_BPF_PROTON_WINE
/* ---- Proton/Wine/Steam-Deck domain (signals 100-108) ----------------------
 * These programs (proton_env, mmap_exec_audit, cross_mem_audit, namespace_entry,
 * module_load_audit, rootfs_ro_audit, compositor_consumer, mprotect_wx_audit,
 * uinput_inject_audit) share hk_ringbuf and are translated here. Built only when
 * the HORKOS_LINUX_EBPF feature set is on AND the proton-wine sub-option is
 * enabled (CMake defines HK_BPF_PROTON_WINE). The BPF-internal tags mirror
 * kernel/linux/bpf/include/hk_bpf_shared.h (HK_BPF_PW_*, 0xB0..0xB8). */
static constexpr uint32_t kBpfTagPwProtonOverride = 0xB0u;
static constexpr uint32_t kBpfTagPwForeignMap     = 0xB1u;
static constexpr uint32_t kBpfTagPwCrossMem       = 0xB2u;
static constexpr uint32_t kBpfTagPwNsEntry        = 0xB3u;
static constexpr uint32_t kBpfTagPwModuleLoad     = 0xB4u;
static constexpr uint32_t kBpfTagPwRootfsRw       = 0xB5u;
static constexpr uint32_t kBpfTagPwFrameConsumer  = 0xB6u;
static constexpr uint32_t kBpfTagPwWxArm          = 0xB7u;
static constexpr uint32_t kBpfTagPwSynthInput     = 0xB8u;

/*
 * HK-TODO(schema): the proton/wine event discriminants (HK_EVENT_PROTON_OVERRIDE
 * =5 .. HK_EVENT_SYNTH_INPUT=13) and their payload structs (24/32/40/32/32/24/24/
 * 40/24) plus the HK_EVENT_PAYLOAD_MAX 16->40 / hk_event_record==64 re-pin are
 * owned by the Schema phase and are NOT yet in the frozen event_schema.h. They are
 * mirrored here as provisional locals so the translate path is ready when the
 * schema lands. The values 5-13 collide pre-Schema with the memory-access and
 * Windows vm_access domains' provisional values — Schema assigns the final
 * distinct discriminants; dispatch by the resolved type once it lands. The Rust
 * mirror server/telemetry/src/linux_proton.rs uses the same provisional values.
 */
static constexpr uint32_t kEvtProtonOverride = 5u;
static constexpr uint32_t kEvtForeignMapPw   = 6u;
static constexpr uint32_t kEvtCrossMem       = 7u;
static constexpr uint32_t kEvtNsEntry        = 8u;
static constexpr uint32_t kEvtModuleLoad     = 9u;
static constexpr uint32_t kEvtRootfsRw       = 10u;
static constexpr uint32_t kEvtFrameConsumer  = 11u;
static constexpr uint32_t kEvtWxArm          = 12u;
static constexpr uint32_t kEvtSynthInput     = 13u;
#endif /* HK_BPF_PROTON_WINE */

#ifdef HK_BPF_MEMORY_ACCESS
/* Memory-access BPF-side tags (mirror the #defines in the new .bpf.c files). */
static constexpr uint32_t kBpfTagPtraceAccess  = 0x30u;
static constexpr uint32_t kBpfTagPtraceTraceme = 0x31u;
static constexpr uint32_t kBpfTagVmWrite       = 0x40u;
static constexpr uint32_t kBpfTagVmRead        = 0x41u;
static constexpr uint32_t kBpfTagProcMemOpen   = 0x50u;
static constexpr uint32_t kBpfTagRwxMap        = 0x60u;
static constexpr uint32_t kBpfTagWxFlip        = 0x61u;
static constexpr uint32_t kBpfTagForeignMap    = 0x62u;
static constexpr uint32_t kBpfTagMemfdCreate   = 0x70u;
static constexpr uint32_t kBpfTagFilelessExec  = 0x71u;
static constexpr uint32_t kBpfTagPhysmemOpen   = 0x80u;
static constexpr uint32_t kBpfTagVmaRow        = 0x90u;

/*
 * HK-TODO(schema): the server event-type discriminants for these memory signals
 * (HK_EVENT_PTRACE_ACCESS=5 .. HK_EVENT_VMA_DRIFT=16) and their payload structs
 * are owned by the Schema phase and are NOT yet present in the frozen
 * sdk/include/horkos/event_schema.h (it is still at HK_EVENT_SCHEMA_VERSION=2,
 * enum tops out at HK_EVENT_HANDLE_OPEN=4). They are mirrored here as local
 * provisional consts so the translation path is ready when the schema lands.
 * NOTE the values 5-8 collide pre-Schema with the Windows vm_access domain's
 * provisional discriminants (server/telemetry/src/vm_access.rs) — the Schema
 * phase assigns the final distinct values; once it lands, replace these with the
 * canonical enum and re-pin sizes against the HK_STATIC_ASSERTs in the header.
 */
static constexpr uint32_t kEvtPtraceAccess  = 5u;
static constexpr uint32_t kEvtPtraceTraceme = 6u;
static constexpr uint32_t kEvtVmWrite       = 7u;
static constexpr uint32_t kEvtVmRead        = 8u;
static constexpr uint32_t kEvtProcMemOpen   = 9u;
static constexpr uint32_t kEvtRwxMap        = 10u;
static constexpr uint32_t kEvtWxFlip        = 11u;
static constexpr uint32_t kEvtMemfdCreate   = 12u;
static constexpr uint32_t kEvtFilelessExec  = 13u;
static constexpr uint32_t kEvtPhysmemOpen   = 14u;
static constexpr uint32_t kEvtForeignMap    = 15u;
static constexpr uint32_t kEvtVmaDrift      = 16u;

/* The memory schema version the new .bpf.c files stamp into every record. Must
 * match HK_SCHEMA_VERSION (3) in those TUs. */
static constexpr uint32_t kMemorySchemaVersion = 3u;
#endif /* HK_BPF_MEMORY_ACCESS */

/* ---- BPF-side event struct layouts --------------------------------------- */
/*
 * These structs are redeclared here (not shared via a common header) so that
 * this translation unit never includes BPF kernel headers (guardrail #4).
 * They must exactly match the structs in the .bpf.c source files.
 * Any layout change in the BPF programs must be reflected here.
 */
static constexpr size_t kBpfPathMax = 256;

struct HkBpfFileOpenEvent {
    uint32_t schema_version;
    uint32_t event_tag;
    uint64_t timestamp_ns;
    uint32_t pid;
    uint32_t reserved;
    char     filename[kBpfPathMax];
};

struct HkBpfPtraceEvent {
    uint32_t schema_version;
    uint32_t event_tag;
    uint64_t timestamp_ns;
    uint32_t pid;
    uint32_t target_pid;
    uint64_t request;
};

struct HkBpfExecEvent {
    uint32_t schema_version;
    uint32_t event_tag;
    uint64_t timestamp_ns;
    uint32_t pid;
    uint32_t parent_pid;
    char     filename[kBpfPathMax];
};

/* ---- Module-trust BPF-side struct mirrors (signals 98/99) ------------------ */
/* Match hk_bpf_devmem_event / hk_bpf_msr_event in lsm_file_open.bpf.c /
 * tracepoints.bpf.c. Always compiled (these extend the core programs). */
struct HkBpfDevmemEvent {        /* lsm_file_open.bpf.c: hk_bpf_devmem_event */
    uint32_t schema_version;
    uint32_t event_tag;
    uint64_t timestamp_ns;
    uint32_t requesting_pid;
    uint32_t dev_minor;
    uint32_t write_intent;
    uint32_t reserved;
};

struct HkBpfMsrEvent {           /* tracepoints.bpf.c: hk_bpf_msr_event */
    uint32_t schema_version;
    uint32_t event_tag;
    uint64_t timestamp_ns;
    uint32_t requesting_pid;
    uint32_t fd;
    uint64_t file_offset;
};

/* ---- Module-trust server-side payload mirrors (HK-TODO(schema)) ------------ */
/* Mirror the impl-plan's hk_event_devmem_access / hk_event_msr_write payloads
 * (each 16 bytes). Sizes pinned so a future schema header diff is caught. */
struct HkEvtDevmemAccess {       /* 16 bytes */
    uint32_t requesting_pid;
    uint32_t dev_minor;
    uint32_t write_intent;
    uint32_t mmap_prot_write;    /* 0 here (mmap correlation is HK-TODO in BPF) */
};
static_assert(sizeof(HkEvtDevmemAccess) == 16,
              "hk_event_devmem_access must be 16 bytes");

struct HkEvtMsrWrite {           /* 16 bytes */
    uint32_t requesting_pid;
    uint32_t msr_index;
    uint32_t sensitive;
    uint32_t reserved;
};
static_assert(sizeof(HkEvtMsrWrite) == 16, "hk_event_msr_write must be 16 bytes");

#ifdef HK_BPF_MEMORY_ACCESS
/* ---- Memory-access BPF-side struct mirrors (match the new .bpf.c records) -- */

struct HkBpfPtraceEvent2 {       /* lsm_ptrace.bpf.c: hk_bpf_ptrace_event */
    uint32_t schema_version;
    uint32_t event_tag;
    uint64_t timestamp_ns;
    uint32_t caller_pid;
    uint32_t target_pid;
    uint32_t mode;
    uint32_t caller_uid;
    int32_t  lsm_ret;
    uint32_t reserved;
};

struct HkBpfVmAccessEvent {      /* fexit_process_vm.bpf.c: hk_bpf_vm_access_event */
    uint32_t schema_version;
    uint32_t event_tag;
    uint64_t timestamp_ns;
    uint32_t caller_pid;
    uint32_t target_pid;
    int64_t  bytes;
};

struct HkBpfProcMemOpenEvent {   /* fentry_proc_mem.bpf.c: hk_bpf_proc_mem_open_event */
    uint32_t schema_version;
    uint32_t event_tag;
    uint64_t timestamp_ns;
    uint32_t caller_pid;
    uint32_t target_pid;
};

struct HkBpfMapAnomalyEvent {    /* lsm_mmap_mprotect.bpf.c: hk_bpf_map_anomaly_event */
    uint32_t schema_version;
    uint32_t event_tag;
    uint64_t timestamp_ns;
    uint32_t caller_pid;
    uint32_t prot;
    uint32_t vm_flags;
    uint32_t reserved;
    uint64_t dev;
    uint64_t inode;
};

struct HkBpfMemfdEvent {         /* memfd_exec.bpf.c: hk_bpf_memfd_event */
    uint32_t schema_version;
    uint32_t event_tag;
    uint64_t timestamp_ns;
    uint32_t pid;
    uint32_t mfd_flags;
    uint64_t inode;
};

struct HkBpfPhysmemEvent {       /* lsm_devmem.bpf.c: hk_bpf_physmem_event */
    uint32_t schema_version;
    uint32_t event_tag;
    uint64_t timestamp_ns;
    uint32_t caller_pid;
    uint32_t rdev;
    uint32_t locked_down;
    uint32_t reserved;
};

struct HkBpfVmaRow {             /* iter_task_vma.bpf.c: hk_bpf_vma_row */
    uint32_t schema_version;
    uint32_t event_tag;
    uint64_t timestamp_ns;
    uint32_t pid;
    uint32_t vm_flags;
    uint64_t vm_start;
    uint64_t vm_end;
    uint64_t dev;
    uint64_t inode;
};

/* ---- Provisional server-side payload mirrors (HK-TODO(schema)) ------------- */
/*
 * These mirror the payload structs the impl-plan adds to event_schema.h once the
 * Schema phase lands them. They are defined locally here so the sink receives a
 * stable, sized payload now. Sizes are pinned with static_assert to the plan's
 * documented byte counts so a future schema header diff is caught.
 */
struct HkEvtPtrace {        /* 24 bytes */
    uint32_t caller_pid;
    uint32_t target_pid;
    uint32_t mode;
    uint32_t caller_uid;
    int32_t  lsm_ret;
    uint32_t reserved;
};
static_assert(sizeof(HkEvtPtrace) == 24, "hk_event_ptrace must be 24 bytes");

struct HkEvtVmAccess {      /* 16 bytes */
    uint32_t caller_pid;
    uint32_t target_pid;
    int64_t  bytes;
};
static_assert(sizeof(HkEvtVmAccess) == 16, "hk_event_vm_access must be 16 bytes");

struct HkEvtProcMemOpen {   /* 8 bytes */
    uint32_t caller_pid;
    uint32_t target_pid;
};
static_assert(sizeof(HkEvtProcMemOpen) == 8, "hk_event_proc_mem_open must be 8 bytes");

struct HkEvtMapAnomaly {    /* 32 bytes */
    uint32_t caller_pid;
    uint32_t prot;
    uint32_t vm_flags;
    uint32_t reserved;
    uint64_t dev;
    uint64_t inode;
};
static_assert(sizeof(HkEvtMapAnomaly) == 32, "hk_event_map_anomaly must be 32 bytes");

struct HkEvtMemfd {         /* 16 bytes */
    uint32_t pid;
    uint32_t mfd_flags;
    uint64_t inode;
};
static_assert(sizeof(HkEvtMemfd) == 16, "hk_event_memfd must be 16 bytes");

struct HkEvtPhysmemOpen {   /* 16 bytes */
    uint32_t caller_pid;
    uint32_t rdev;
    uint32_t locked_down;
    uint32_t reserved;
};
static_assert(sizeof(HkEvtPhysmemOpen) == 16, "hk_event_physmem_open must be 16 bytes");

struct HkEvtVmaRow {        /* 40 bytes */
    uint32_t pid;
    uint32_t vm_flags;
    uint64_t vm_start;
    uint64_t vm_end;
    uint64_t dev;
    uint64_t inode;
};
static_assert(sizeof(HkEvtVmaRow) == 40, "hk_event_vma_row must be 40 bytes");
#endif /* HK_BPF_MEMORY_ACCESS */

#ifdef HK_BPF_PROTON_WINE
/* ---- Proton/Wine/Deck BPF-side struct mirrors -----------------------------
 * Exact layout mirrors of the structs in kernel/linux/bpf/include/hk_bpf_shared.h
 * (struct hk_bpf_pw_*). Redeclared here so this TU never includes BPF headers
 * (guardrail #4). Any layout change in hk_bpf_shared.h must be reflected here. */
struct HkBpfPwProtonOverride {
    uint32_t schema_version;
    uint32_t event_tag;
    uint64_t timestamp_ns;
    uint32_t pid;
    uint32_t flags;
    uint64_t override_token_hash;
    uint64_t proton_build_hash;
};

struct HkBpfPwForeignMap {
    uint32_t schema_version;
    uint32_t event_tag;
    uint64_t timestamp_ns;
    uint32_t pid;
    uint32_t prot_flags;
    uint64_t map_base;
    uint64_t backing_inode;
    uint32_t backing_dev;
    uint32_t map_flags;
};

struct HkBpfPwCrossMem {
    uint32_t schema_version;
    uint32_t event_tag;
    uint64_t timestamp_ns;
    uint32_t caller_tgid;
    uint32_t target_tgid;
    uint32_t access_kind;
    uint32_t flags;
    uint64_t remote_addr;
    uint64_t remote_len;
    uint64_t event_time_ns;
};

struct HkBpfPwNsEntry {
    uint32_t schema_version;
    uint32_t event_tag;
    uint64_t timestamp_ns;
    uint32_t caller_tgid;
    uint32_t target_ns_type;
    uint64_t target_ns_inode;
    uint64_t game_ns_inode;
    uint32_t flags;
    uint32_t reserved;
};

struct HkBpfPwModuleLoad {
    uint32_t schema_version;
    uint32_t event_tag;
    uint64_t timestamp_ns;
    uint32_t initiator_tgid;
    uint32_t flags;
    uint64_t module_name_hash;
    uint64_t module_sig_hash;
    uint64_t event_time_ns;
};

struct HkBpfPwRootfsRw {
    uint32_t schema_version;
    uint32_t event_tag;
    uint64_t timestamp_ns;
    uint32_t actor_tgid;
    uint32_t flags;
    uint64_t target_path_hash;
    uint64_t event_time_ns;
};

struct HkBpfPwFrameConsumer {
    uint32_t schema_version;
    uint32_t event_tag;
    uint64_t timestamp_ns;
    uint32_t consumer_tgid;
    uint32_t flags;
    uint64_t socket_or_fb_hash;
    uint64_t event_time_ns;
};

struct HkBpfPwWxArm {
    uint32_t schema_version;
    uint32_t event_tag;
    uint64_t timestamp_ns;
    uint32_t pid;
    uint32_t new_prot;
    uint64_t vma_start;
    uint64_t vma_end;
    uint64_t backing_inode;
    uint32_t backing_dev;
    uint32_t flags;
};

struct HkBpfPwSynthInput {
    uint32_t schema_version;
    uint32_t event_tag;
    uint64_t timestamp_ns;
    uint32_t injector_tgid;
    uint32_t flags;
    uint32_t ev_type;
    uint32_t ev_code;
    uint64_t event_time_ns;
};

/* ---- Proton/Wine/Deck server-side payload mirrors (HK-TODO(schema)) --------
 * Mirror the impl-plan's event_schema.h payloads (sizes pinned to the documented
 * byte counts so a future schema header diff is caught). */
struct HkEvtProtonOverride {   /* 24 bytes */
    uint32_t pid;
    uint32_t flags;
    uint64_t override_token_hash;
    uint64_t proton_build_hash;
};
static_assert(sizeof(HkEvtProtonOverride) == 24, "hk_event_proton_override must be 24 bytes");

struct HkEvtForeignMapPw {     /* 32 bytes */
    uint32_t pid;
    uint32_t prot_flags;
    uint64_t map_base;
    uint64_t backing_inode;
    uint32_t backing_dev;
    uint32_t map_flags;
};
static_assert(sizeof(HkEvtForeignMapPw) == 32, "hk_event_foreign_map must be 32 bytes");

struct HkEvtCrossMem {         /* 40 bytes */
    uint32_t caller_tgid;
    uint32_t target_tgid;
    uint32_t access_kind;
    uint32_t flags;
    uint64_t remote_addr;
    uint64_t remote_len;
    uint64_t event_time_ns;
};
static_assert(sizeof(HkEvtCrossMem) == 40, "hk_event_cross_mem must be 40 bytes");

struct HkEvtNsEntry {          /* 32 bytes */
    uint32_t caller_tgid;
    uint32_t target_ns_type;
    uint64_t target_ns_inode;
    uint64_t game_ns_inode;
    uint32_t flags;
    uint32_t reserved;
};
static_assert(sizeof(HkEvtNsEntry) == 32, "hk_event_ns_entry must be 32 bytes");

struct HkEvtModuleLoad {       /* 32 bytes */
    uint32_t initiator_tgid;
    uint32_t flags;
    uint64_t module_name_hash;
    uint64_t module_sig_hash;
    uint64_t event_time_ns;
};
static_assert(sizeof(HkEvtModuleLoad) == 32, "hk_event_module_load must be 32 bytes");

struct HkEvtRootfsRw {         /* 24 bytes */
    uint32_t actor_tgid;
    uint32_t flags;
    uint64_t target_path_hash;
    uint64_t event_time_ns;
};
static_assert(sizeof(HkEvtRootfsRw) == 24, "hk_event_rootfs_rw must be 24 bytes");

struct HkEvtFrameConsumer {    /* 24 bytes */
    uint32_t consumer_tgid;
    uint32_t flags;
    uint64_t socket_or_fb_hash;
    uint64_t event_time_ns;
};
static_assert(sizeof(HkEvtFrameConsumer) == 24, "hk_event_frame_consumer must be 24 bytes");

struct HkEvtWxArm {            /* 40 bytes */
    uint32_t pid;
    uint32_t new_prot;
    uint64_t vma_start;
    uint64_t vma_end;
    uint64_t backing_inode;
    uint32_t backing_dev;
    uint32_t flags;
};
static_assert(sizeof(HkEvtWxArm) == 40, "hk_event_wx_arm must be 40 bytes");

struct HkEvtSynthInput {       /* 24 bytes */
    uint32_t injector_tgid;
    uint32_t flags;
    uint32_t ev_type;
    uint32_t ev_code;
    uint64_t event_time_ns;
};
static_assert(sizeof(HkEvtSynthInput) == 24, "hk_event_synth_input must be 24 bytes");
#endif /* HK_BPF_PROTON_WINE */

/* ---- Internal loader state ----------------------------------------------- */

struct LoaderState {
    lsm_file_open_bpf *lsm_skel   = nullptr;
    tracepoints_bpf   *tp_skel    = nullptr;
    ring_buffer       *ringbuf    = nullptr;
    HkEventSink        sink       = nullptr;
    std::atomic<bool>  stop_flag  { false };

#ifdef HK_BPF_MEMORY_ACCESS
    lsm_ptrace_bpf        *ptrace_skel   = nullptr;
    fexit_process_vm_bpf  *vm_skel       = nullptr;
    fentry_proc_mem_bpf   *procmem_skel  = nullptr;
    lsm_mmap_mprotect_bpf *mmap_skel     = nullptr;
    memfd_exec_bpf        *memfd_skel    = nullptr;
    lsm_devmem_bpf        *devmem_skel   = nullptr;
    iter_task_vma_bpf     *vma_skel      = nullptr;
    bool                   vma_available = false;  /* iter/task_vma loaded (kernel >= 5.13) */
    struct bpf_link       *vma_link      = nullptr; /* iterator link (owns vma_iter_fd) */
    int                    vma_iter_fd   = -1;     /* iterator link fd for the scan trigger */

    /* memfd<->exec correlation LRU (impl-plan §77). Keyed by (tgid, inode); the
     * value is the create timestamp so stale entries TTL out. A HK_BPF_FILELESS_
     * EXEC tag is only promoted to a confirmed fileless-exec emit when a matching
     * recent memfd create exists for the same (tgid, inode). */
    std::unordered_map<uint64_t, uint64_t> memfd_join;  /* key=(tgid<<32|inode32) -> ts_ns */
#endif
};

static LoaderState g_state;

#ifdef HK_BPF_PROTON_WINE
/* ---- Proton/Wine/Deck verifier singletons + wineserver resolution ---------
 * The classifiers are constructed with empty baselines here. The host-integrity
 * aggregator injects the real manifests/allowlists/lineage/session-start when it
 * wires the loader up; until then the verifiers run report-only (no suppression),
 * which is the correct fail-open posture for a sample-and-report client. */
struct ProtonWineState {
    /* Empty FP allowlist + builtin-only set: every native override is reported
     * (off-manifest) until ProtonOverrideCheck is seeded with the per-version
     * manifest. on_dist_path defaults false (no dist-tree knowledge yet). */
    horkos::proton::ProtonOverrideClassifier proton{ {}, {} };
    horkos::prefixmap::PrefixMapClassifier    prefix{ {}, {} };
    horkos::containerns::ContainerNsBaseline  container_ns{ {}, {}, nullptr };
    horkos::deckmod::DeckModuleBaseline       deck_mod{ {}, {}, nullptr };
    horkos::deckrootfs::DeckRootfsBaseline    deck_rootfs{ false, nullptr };
    horkos::framecons::GamescopeConsumerBaseline frame_cons{ {} };
    horkos::winebuiltin::WineBuiltinIntegrity wine_builtin{ {} };
    horkos::deckinput::DeckInputBaseline      deck_input{ {}, 0 };

    /* The game's resolved wineserver tgid (catalog places this resolution in the
     * loader). 0 = not yet resolved; a cross_mem caller matching it is tagged
     * WINESERVER (reported, never dropped). The Horkos client's own tgid is the
     * self-allowlist. Both are injected by the aggregator at session start. */
    uint32_t wineserver_tgid = 0;
    uint32_t horkos_self_tgid = 0;
};

static ProtonWineState g_pw;

/* Enrich a cross_mem record's flags from the resolved wineserver/self tgids. This
 * is the loader-side allowlisting the catalog assigns to Loader.cpp; it only SETS
 * reported flags (WINESERVER/HORKOS_SELF), never drops the record. */
static uint32_t pw_enrich_cross_mem(uint32_t caller_tgid, uint32_t kernel_flags) {
    uint32_t flags = kernel_flags;
    if (g_pw.wineserver_tgid != 0 && caller_tgid == g_pw.wineserver_tgid)
        flags |= 0x1u; /* HK_PW_XMEM_FLAG_WINESERVER */
    if (g_pw.horkos_self_tgid != 0 && caller_tgid == g_pw.horkos_self_tgid)
        flags |= 0x2u; /* HK_PW_XMEM_FLAG_HORKOS_SELF */
    return flags;
}
#endif /* HK_BPF_PROTON_WINE */

#ifdef HK_BPF_MEMORY_ACCESS
/* TTL for the memfd<->exec correlation window. A create older than this is not
 * joined to an exec (the exec is treated as unrelated). 5s is generous for the
 * create->write->execveat sequence while bounding the map. */
static constexpr uint64_t kMemfdJoinTtlNs = 5ull * 1000ull * 1000ull * 1000ull;

/* Fold a (tgid, inode) into the 64-bit join-map key. inode is truncated to 32
 * bits: anon-shmem inode numbers are small and the tgid disambiguates collisions
 * across processes; a same-tgid inode-low collision across two memfds within the
 * TTL window is acceptable (worst case: one spurious join, still evidence). */
static inline uint64_t memfd_join_key(uint32_t tgid, uint64_t inode)
{
    return (static_cast<uint64_t>(tgid) << 32) | static_cast<uint32_t>(inode & 0xFFFFFFFFu);
}

/* Evict join entries older than the TTL relative to `now_ns`. Called on each
 * create so the map cannot grow unbounded under a memfd flood. */
static void memfd_join_evict(uint64_t now_ns)
{
    for (auto it = g_state.memfd_join.begin(); it != g_state.memfd_join.end(); ) {
        if (now_ns - it->second > kMemfdJoinTtlNs)
            it = g_state.memfd_join.erase(it);
        else
            ++it;
    }
}
#endif /* HK_BPF_MEMORY_ACCESS */

/* ---- Ring-buffer callback ------------------------------------------------ */
/*
 * Called by ring_buffer__poll for each record committed to hk_ringbuf.
 * Translates the compact BPF event into an hk_event_record and invokes
 * the caller-supplied sink.
 *
 * Return 0 to continue polling; negative to abort.
 * Reference: https://libbpf.readthedocs.io/en/latest/api.html#c.ring_buffer_sample_fn
 */
static int on_ringbuf_sample(void *ctx, void *data, size_t data_sz)
{
    (void)ctx;

    if (data_sz < sizeof(uint32_t) * 2) {
        /* Too small to contain schema_version + event_tag — corrupted record. */
        return 0;
    }

    /* Peek at the tag without aliasing the union through an untyped cast.
     * memcpy is the standards-compliant way to read a field from an opaque
     * buffer without triggering strict-aliasing UB. */
    uint32_t event_tag = 0;
    std::memcpy(&event_tag,
                static_cast<const char *>(data) + offsetof(HkBpfFileOpenEvent, event_tag),
                sizeof(event_tag));

    hk_event_header  hdr  {};
    hdr.version  = HK_EVENT_SCHEMA_VERSION;
    hdr.reserved = 0;

    /*
     * For each event tag, validate the expected minimum size, populate the
     * hk_event_header, and call the sink with a pointer to the translated
     * payload.  We pass (header, payload_ptr, payload_size) rather than a
     * flattened buffer to avoid a heap allocation on the hot path.
     */
    if (event_tag == kBpfTagFileOpen) {
        if (data_sz < sizeof(HkBpfFileOpenEvent)) return 0;
        HkBpfFileOpenEvent bpf_evt {};
        std::memcpy(&bpf_evt, data, sizeof(bpf_evt));

        /* Map BPF file-open to HK_EVENT_HANDLE_OPEN (closest schema match;
         * the server treats it as a watched-file-access event). */
        hdr.type          = HK_EVENT_HANDLE_OPEN;
        hdr.timestamp_ns  = bpf_evt.timestamp_ns;

        hk_event_handle_open payload {};
        payload.requesting_pid = bpf_evt.pid;
        payload.target_pid     = 0;        /* not available at this hook point */
        payload.access_mask    = 0;        /* not available at LSM file_open    */
        payload.reserved       = 0;
        hdr.payload_bytes = static_cast<uint32_t>(sizeof(payload));

        if (g_state.sink)
            g_state.sink(&hdr, &payload);

    } else if (event_tag == kBpfTagPtrace) {
        if (data_sz < sizeof(HkBpfPtraceEvent)) return 0;
        HkBpfPtraceEvent bpf_evt {};
        std::memcpy(&bpf_evt, data, sizeof(bpf_evt));

        /* Map ptrace to HK_EVENT_HANDLE_OPEN: requesting_pid is the tracer,
         * target_pid is the tracee, access_mask encodes the ptrace request. */
        hdr.type          = HK_EVENT_HANDLE_OPEN;
        hdr.timestamp_ns  = bpf_evt.timestamp_ns;

        hk_event_handle_open payload {};
        payload.requesting_pid = bpf_evt.pid;
        payload.target_pid     = bpf_evt.target_pid;
        /* Truncate 64-bit request to 32-bit access_mask field; the server
         * interprets the upper bits as reserved and masks them off. */
        payload.access_mask    = static_cast<uint32_t>(bpf_evt.request & 0xFFFFFFFFu);
        payload.reserved       = 0;
        hdr.payload_bytes = static_cast<uint32_t>(sizeof(payload));

        if (g_state.sink)
            g_state.sink(&hdr, &payload);

    } else if (event_tag == kBpfTagProcExec) {
        if (data_sz < sizeof(HkBpfExecEvent)) return 0;
        HkBpfExecEvent bpf_evt {};
        std::memcpy(&bpf_evt, data, sizeof(bpf_evt));

        hdr.type          = HK_EVENT_PROCESS_CREATE;
        hdr.timestamp_ns  = bpf_evt.timestamp_ns;

        hk_event_process_create payload {};
        payload.pid         = bpf_evt.pid;
        payload.parent_pid  = bpf_evt.parent_pid;
        /* create_time_ns: exec timestamp serves as a best-effort proxy;
         * note the epoch mismatch documented in event_schema.h — the server
         * must not compare this directly with header.timestamp_ns. */
        payload.create_time_ns = bpf_evt.timestamp_ns;
        hdr.payload_bytes = static_cast<uint32_t>(sizeof(payload));

        if (g_state.sink)
            g_state.sink(&hdr, &payload);

    } else if (event_tag == kBpfTagDevmem) {
        if (data_sz < sizeof(HkBpfDevmemEvent)) return 0;
        HkBpfDevmemEvent bpf_evt {};
        std::memcpy(&bpf_evt, data, sizeof(bpf_evt));

        /* Signal 98: /dev/mem|kmem|port open with write-intent. The BPF side
         * already resolved the device minor + FMODE_WRITE; no userspace fd walk
         * needed here. */
        hdr.type         = kEvtDevmemAccess;
        hdr.timestamp_ns = bpf_evt.timestamp_ns;

        HkEvtDevmemAccess payload {};
        payload.requesting_pid  = bpf_evt.requesting_pid;
        payload.dev_minor       = bpf_evt.dev_minor;
        payload.write_intent    = bpf_evt.write_intent;
        payload.mmap_prot_write = 0;   /* mmap correlation is HK-TODO in BPF */
        hdr.payload_bytes = static_cast<uint32_t>(sizeof(payload));
        if (g_state.sink) g_state.sink(&hdr, &payload);

    } else if (event_tag == kBpfTagMsrWrite) {
        if (data_sz < sizeof(HkBpfMsrEvent)) return 0;
        HkBpfMsrEvent bpf_evt {};
        std::memcpy(&bpf_evt, data, sizeof(bpf_evt));

        /* Signal 99: the BPF side emitted a raw (pid, fd, offset) for a pwrite64.
         * Resolve the fd→device in userspace (§1.2 / §7-A): drop the record unless
         * the fd is an /dev/cpu/N/msr node. The pwrite64 offset is the MSR index;
         * classify its sensitivity. A non-msr fd or an unresolvable fd is silently
         * dropped (coverage, never a false MSR detection). */
        if (!horkos::modint::ResolveFdIsMsr(bpf_evt.requesting_pid, bpf_evt.fd)) {
            return 0;
        }
        hdr.type         = kEvtMsrWriteSensitive;
        hdr.timestamp_ns = bpf_evt.timestamp_ns;

        HkEvtMsrWrite payload {};
        payload.requesting_pid = bpf_evt.requesting_pid;
        payload.msr_index      = static_cast<uint32_t>(bpf_evt.file_offset & 0xFFFFFFFFu);
        payload.sensitive      =
            horkos::modint::IsSensitiveMsr(bpf_evt.file_offset) ? 1u : 0u;
        payload.reserved       = 0;
        hdr.payload_bytes = static_cast<uint32_t>(sizeof(payload));
        if (g_state.sink) g_state.sink(&hdr, &payload);

    }
#ifdef HK_BPF_MEMORY_ACCESS
    else if (event_tag == kBpfTagPtraceAccess || event_tag == kBpfTagPtraceTraceme) {
        if (data_sz < sizeof(HkBpfPtraceEvent2)) return 0;
        HkBpfPtraceEvent2 bpf_evt {};
        std::memcpy(&bpf_evt, data, sizeof(bpf_evt));

        hdr.type         = (event_tag == kBpfTagPtraceAccess)
                           ? kEvtPtraceAccess : kEvtPtraceTraceme;
        hdr.timestamp_ns = bpf_evt.timestamp_ns;

        HkEvtPtrace payload {};
        payload.caller_pid = bpf_evt.caller_pid;
        payload.target_pid = bpf_evt.target_pid;
        payload.mode       = bpf_evt.mode;
        payload.caller_uid = bpf_evt.caller_uid;
        payload.lsm_ret    = bpf_evt.lsm_ret;
        payload.reserved   = 0;
        hdr.payload_bytes  = static_cast<uint32_t>(sizeof(payload));
        if (g_state.sink) g_state.sink(&hdr, &payload);

    } else if (event_tag == kBpfTagVmWrite || event_tag == kBpfTagVmRead) {
        if (data_sz < sizeof(HkBpfVmAccessEvent)) return 0;
        HkBpfVmAccessEvent bpf_evt {};
        std::memcpy(&bpf_evt, data, sizeof(bpf_evt));

        hdr.type         = (event_tag == kBpfTagVmWrite) ? kEvtVmWrite : kEvtVmRead;
        hdr.timestamp_ns = bpf_evt.timestamp_ns;

        HkEvtVmAccess payload {};
        payload.caller_pid = bpf_evt.caller_pid;
        payload.target_pid = bpf_evt.target_pid;
        payload.bytes      = bpf_evt.bytes;
        hdr.payload_bytes  = static_cast<uint32_t>(sizeof(payload));
        if (g_state.sink) g_state.sink(&hdr, &payload);

    } else if (event_tag == kBpfTagProcMemOpen) {
        if (data_sz < sizeof(HkBpfProcMemOpenEvent)) return 0;
        HkBpfProcMemOpenEvent bpf_evt {};
        std::memcpy(&bpf_evt, data, sizeof(bpf_evt));

        hdr.type         = kEvtProcMemOpen;
        hdr.timestamp_ns = bpf_evt.timestamp_ns;

        HkEvtProcMemOpen payload {};
        payload.caller_pid = bpf_evt.caller_pid;
        payload.target_pid = bpf_evt.target_pid;
        hdr.payload_bytes  = static_cast<uint32_t>(sizeof(payload));
        if (g_state.sink) g_state.sink(&hdr, &payload);

    } else if (event_tag == kBpfTagRwxMap || event_tag == kBpfTagWxFlip ||
               event_tag == kBpfTagForeignMap) {
        if (data_sz < sizeof(HkBpfMapAnomalyEvent)) return 0;
        HkBpfMapAnomalyEvent bpf_evt {};
        std::memcpy(&bpf_evt, data, sizeof(bpf_evt));

        hdr.type = (event_tag == kBpfTagRwxMap)   ? kEvtRwxMap
                 : (event_tag == kBpfTagWxFlip)   ? kEvtWxFlip
                 :                                  kEvtForeignMap;
        hdr.timestamp_ns = bpf_evt.timestamp_ns;

        HkEvtMapAnomaly payload {};
        payload.caller_pid = bpf_evt.caller_pid;
        payload.prot       = bpf_evt.prot;
        payload.vm_flags   = bpf_evt.vm_flags;
        payload.reserved   = 0;
        payload.dev        = bpf_evt.dev;
        payload.inode      = bpf_evt.inode;
        hdr.payload_bytes  = static_cast<uint32_t>(sizeof(payload));
        if (g_state.sink) g_state.sink(&hdr, &payload);

    } else if (event_tag == kBpfTagMemfdCreate) {
        if (data_sz < sizeof(HkBpfMemfdEvent)) return 0;
        HkBpfMemfdEvent bpf_evt {};
        std::memcpy(&bpf_evt, data, sizeof(bpf_evt));

        /* Record the create in the join LRU so a subsequent fileless-exec of the
         * same (tgid,inode) inside the TTL can be confirmed. The create tag is
         * emitted unconditionally (cheap/common evidence). */
        memfd_join_evict(bpf_evt.timestamp_ns);
        g_state.memfd_join[memfd_join_key(bpf_evt.pid, bpf_evt.inode)] =
            bpf_evt.timestamp_ns;

        hdr.type         = kEvtMemfdCreate;
        hdr.timestamp_ns = bpf_evt.timestamp_ns;

        HkEvtMemfd payload {};
        payload.pid       = bpf_evt.pid;
        payload.mfd_flags = bpf_evt.mfd_flags;
        payload.inode     = bpf_evt.inode;
        hdr.payload_bytes = static_cast<uint32_t>(sizeof(payload));
        if (g_state.sink) g_state.sink(&hdr, &payload);

    } else if (event_tag == kBpfTagFilelessExec) {
        if (data_sz < sizeof(HkBpfMemfdEvent)) return 0;
        HkBpfMemfdEvent bpf_evt {};
        std::memcpy(&bpf_evt, data, sizeof(bpf_evt));

        /* CROSS-HOOK JOIN (impl-plan §77): only promote to a confirmed fileless-
         * exec when this tgid created a memfd with a matching inode inside the
         * TTL window. An empty-name exec with no recorded matching create is a
         * non-memfd anon exec (or a missed create) — not emitted here to hold the
         * FP budget; the bare create tag already carries that weaker evidence. */
        memfd_join_evict(bpf_evt.timestamp_ns);
        uint64_t key = memfd_join_key(bpf_evt.pid, bpf_evt.inode);
        auto it = g_state.memfd_join.find(key);
        if (it == g_state.memfd_join.end())
            return 0;   /* no matching create — do not emit the confirmed tag */
        g_state.memfd_join.erase(it);   /* consume the join (one exec per create) */

        hdr.type         = kEvtFilelessExec;
        hdr.timestamp_ns = bpf_evt.timestamp_ns;

        HkEvtMemfd payload {};
        payload.pid       = bpf_evt.pid;
        payload.mfd_flags = bpf_evt.mfd_flags;
        payload.inode     = bpf_evt.inode;
        hdr.payload_bytes = static_cast<uint32_t>(sizeof(payload));
        if (g_state.sink) g_state.sink(&hdr, &payload);

    } else if (event_tag == kBpfTagPhysmemOpen) {
        if (data_sz < sizeof(HkBpfPhysmemEvent)) return 0;
        HkBpfPhysmemEvent bpf_evt {};
        std::memcpy(&bpf_evt, data, sizeof(bpf_evt));

        hdr.type         = kEvtPhysmemOpen;
        hdr.timestamp_ns = bpf_evt.timestamp_ns;

        HkEvtPhysmemOpen payload {};
        payload.caller_pid  = bpf_evt.caller_pid;
        payload.rdev        = bpf_evt.rdev;
        payload.locked_down = bpf_evt.locked_down;
        payload.reserved    = 0;
        hdr.payload_bytes   = static_cast<uint32_t>(sizeof(payload));
        if (g_state.sink) g_state.sink(&hdr, &payload);

    } else if (event_tag == kBpfTagVmaRow) {
        if (data_sz < sizeof(HkBpfVmaRow)) return 0;
        HkBpfVmaRow bpf_evt {};
        std::memcpy(&bpf_evt, data, sizeof(bpf_evt));

        hdr.type         = kEvtVmaDrift;
        hdr.timestamp_ns = bpf_evt.timestamp_ns;

        HkEvtVmaRow payload {};
        payload.pid      = bpf_evt.pid;
        payload.vm_flags = bpf_evt.vm_flags;
        payload.vm_start = bpf_evt.vm_start;
        payload.vm_end   = bpf_evt.vm_end;
        payload.dev      = bpf_evt.dev;
        payload.inode    = bpf_evt.inode;
        hdr.payload_bytes = static_cast<uint32_t>(sizeof(payload));
        if (g_state.sink) g_state.sink(&hdr, &payload);

    }
#endif /* HK_BPF_MEMORY_ACCESS */
#ifdef HK_BPF_PROTON_WINE
    else if (event_tag == kBpfTagPwProtonOverride) {
        if (data_sz < sizeof(HkBpfPwProtonOverride)) return 0;
        HkBpfPwProtonOverride bpf_evt {};
        std::memcpy(&bpf_evt, data, sizeof(bpf_evt));

        hdr.type         = kEvtProtonOverride;
        hdr.timestamp_ns = bpf_evt.timestamp_ns;

        /* The BPF side only hashed the offending token; the manifest diff is here.
         * We cannot re-derive the raw "dll=order" string from the FNV hash, so the
         * classifier runs against the userspace-resolved token (from
         * /proc/<pid>/environ) when the aggregator supplies it; absent that, the
         * kernel flags (0) ride through report-only. */
        HkEvtProtonOverride payload {};
        payload.pid                 = bpf_evt.pid;
        payload.flags               = bpf_evt.flags;  /* enriched by aggregator seam */
        payload.override_token_hash = bpf_evt.override_token_hash;
        payload.proton_build_hash   = bpf_evt.proton_build_hash;
        hdr.payload_bytes = static_cast<uint32_t>(sizeof(payload));
        if (g_state.sink) g_state.sink(&hdr, &payload);

    } else if (event_tag == kBpfTagPwForeignMap) {
        if (data_sz < sizeof(HkBpfPwForeignMap)) return 0;
        HkBpfPwForeignMap bpf_evt {};
        std::memcpy(&bpf_evt, data, sizeof(bpf_evt));

        hdr.type         = kEvtForeignMapPw;
        hdr.timestamp_ns = bpf_evt.timestamp_ns;

        /* PrefixMapClassifier resolves the off-tree decision from the maps path;
         * the path is re-resolved userspace (the BPF side carries only dev:ino +
         * kernel map_flags). With an empty path here the classifier preserves the
         * kernel flags (report-only). */
        HkEvtForeignMapPw payload {};
        payload.pid           = bpf_evt.pid;
        payload.prot_flags    = bpf_evt.prot_flags;
        payload.map_base      = bpf_evt.map_base;
        payload.backing_inode = bpf_evt.backing_inode;
        payload.backing_dev   = bpf_evt.backing_dev;
        payload.map_flags     = g_pw.prefix.ClassifyMap(std::string(), bpf_evt.map_flags);
        hdr.payload_bytes = static_cast<uint32_t>(sizeof(payload));
        if (g_state.sink) g_state.sink(&hdr, &payload);

    } else if (event_tag == kBpfTagPwCrossMem) {
        if (data_sz < sizeof(HkBpfPwCrossMem)) return 0;
        HkBpfPwCrossMem bpf_evt {};
        std::memcpy(&bpf_evt, data, sizeof(bpf_evt));

        hdr.type         = kEvtCrossMem;
        hdr.timestamp_ns = bpf_evt.timestamp_ns;

        HkEvtCrossMem payload {};
        payload.caller_tgid   = bpf_evt.caller_tgid;
        payload.target_tgid   = bpf_evt.target_tgid;
        payload.access_kind   = bpf_evt.access_kind;
        /* Loader-side wineserver/self allowlisting (catalog places it here). Only
         * SETS reported flags; never drops the record (server adjudicates). */
        payload.flags         = pw_enrich_cross_mem(bpf_evt.caller_tgid, bpf_evt.flags);
        payload.remote_addr   = bpf_evt.remote_addr;
        payload.remote_len    = bpf_evt.remote_len;
        payload.event_time_ns = bpf_evt.event_time_ns;
        hdr.payload_bytes = static_cast<uint32_t>(sizeof(payload));
        if (g_state.sink) g_state.sink(&hdr, &payload);

    } else if (event_tag == kBpfTagPwNsEntry) {
        if (data_sz < sizeof(HkBpfPwNsEntry)) return 0;
        HkBpfPwNsEntry bpf_evt {};
        std::memcpy(&bpf_evt, data, sizeof(bpf_evt));

        hdr.type         = kEvtNsEntry;
        hdr.timestamp_ns = bpf_evt.timestamp_ns;

        HkEvtNsEntry payload {};
        payload.caller_tgid     = bpf_evt.caller_tgid;
        payload.target_ns_type  = bpf_evt.target_ns_type;
        payload.target_ns_inode = bpf_evt.target_ns_inode;
        /* game_ns_inode + lineage flags are filled by ContainerNsBaseline once the
         * aggregator seeds the launcher lineage + game ns inodes. */
        payload.game_ns_inode   = bpf_evt.game_ns_inode;
        payload.flags           = bpf_evt.flags |
            g_pw.container_ns.ClassifyNsEntry(bpf_evt.caller_tgid,
                                              bpf_evt.target_ns_inode,
                                              /*is_dev_nsenter=*/false);
        payload.reserved        = 0;
        hdr.payload_bytes = static_cast<uint32_t>(sizeof(payload));
        if (g_state.sink) g_state.sink(&hdr, &payload);

    } else if (event_tag == kBpfTagPwModuleLoad) {
        if (data_sz < sizeof(HkBpfPwModuleLoad)) return 0;
        HkBpfPwModuleLoad bpf_evt {};
        std::memcpy(&bpf_evt, data, sizeof(bpf_evt));

        hdr.type         = kEvtModuleLoad;
        hdr.timestamp_ns = bpf_evt.timestamp_ns;

        HkEvtModuleLoad payload {};
        payload.initiator_tgid  = bpf_evt.initiator_tgid;
        payload.flags           = bpf_evt.flags |
            g_pw.deck_mod.ClassifyModuleLoad(bpf_evt.module_name_hash,
                                             bpf_evt.event_time_ns);
        payload.module_name_hash = bpf_evt.module_name_hash;
        payload.module_sig_hash  = bpf_evt.module_sig_hash;
        payload.event_time_ns    = bpf_evt.event_time_ns;
        hdr.payload_bytes = static_cast<uint32_t>(sizeof(payload));
        if (g_state.sink) g_state.sink(&hdr, &payload);

    } else if (event_tag == kBpfTagPwRootfsRw) {
        if (data_sz < sizeof(HkBpfPwRootfsRw)) return 0;
        HkBpfPwRootfsRw bpf_evt {};
        std::memcpy(&bpf_evt, data, sizeof(bpf_evt));

        hdr.type         = kEvtRootfsRw;
        hdr.timestamp_ns = bpf_evt.timestamp_ns;

        HkEvtRootfsRw payload {};
        payload.actor_tgid      = bpf_evt.actor_tgid;
        payload.flags           =
            g_pw.deck_rootfs.ClassifyRootfsRw(bpf_evt.flags, bpf_evt.event_time_ns);
        payload.target_path_hash = bpf_evt.target_path_hash;
        payload.event_time_ns    = bpf_evt.event_time_ns;
        hdr.payload_bytes = static_cast<uint32_t>(sizeof(payload));
        if (g_state.sink) g_state.sink(&hdr, &payload);

    } else if (event_tag == kBpfTagPwFrameConsumer) {
        if (data_sz < sizeof(HkBpfPwFrameConsumer)) return 0;
        HkBpfPwFrameConsumer bpf_evt {};
        std::memcpy(&bpf_evt, data, sizeof(bpf_evt));

        hdr.type         = kEvtFrameConsumer;
        hdr.timestamp_ns = bpf_evt.timestamp_ns;

        HkEvtFrameConsumer payload {};
        payload.consumer_tgid    = bpf_evt.consumer_tgid;
        payload.flags            =
            g_pw.frame_cons.ClassifyConsumer(bpf_evt.consumer_tgid, bpf_evt.flags);
        payload.socket_or_fb_hash = bpf_evt.socket_or_fb_hash;
        payload.event_time_ns     = bpf_evt.event_time_ns;
        hdr.payload_bytes = static_cast<uint32_t>(sizeof(payload));
        if (g_state.sink) g_state.sink(&hdr, &payload);

    } else if (event_tag == kBpfTagPwWxArm) {
        if (data_sz < sizeof(HkBpfPwWxArm)) return 0;
        HkBpfPwWxArm bpf_evt {};
        std::memcpy(&bpf_evt, data, sizeof(bpf_evt));

        hdr.type         = kEvtWxArm;
        hdr.timestamp_ns = bpf_evt.timestamp_ns;

        /* The inode-arm classification (WineBuiltinIntegrity) needs the live maps
         * walk + on-disk SHA, an aggregator-supplied seam (see WineBuiltinIntegrity
         * HK-UNCERTAIN). Here we forward the kernel's WAS_RX + dev:ino so the server
         * has the W^X transition evidence; the inode-mismatch verdict is enriched by
         * the aggregator when the manifest is present. */
        HkEvtWxArm payload {};
        payload.pid           = bpf_evt.pid;
        payload.new_prot      = bpf_evt.new_prot;
        payload.vma_start     = bpf_evt.vma_start;
        payload.vma_end       = bpf_evt.vma_end;
        payload.backing_inode = bpf_evt.backing_inode;
        payload.backing_dev   = bpf_evt.backing_dev;
        payload.flags         = bpf_evt.flags;
        hdr.payload_bytes = static_cast<uint32_t>(sizeof(payload));
        if (g_state.sink) g_state.sink(&hdr, &payload);

    } else if (event_tag == kBpfTagPwSynthInput) {
        if (data_sz < sizeof(HkBpfPwSynthInput)) return 0;
        HkBpfPwSynthInput bpf_evt {};
        std::memcpy(&bpf_evt, data, sizeof(bpf_evt));

        hdr.type         = kEvtSynthInput;
        hdr.timestamp_ns = bpf_evt.timestamp_ns;

        HkEvtSynthInput payload {};
        payload.injector_tgid = bpf_evt.injector_tgid;
        payload.flags         =
            g_pw.deck_input.ClassifyInput(bpf_evt.injector_tgid, bpf_evt.flags,
                                          bpf_evt.event_time_ns);
        payload.ev_type       = bpf_evt.ev_type;
        payload.ev_code       = bpf_evt.ev_code;
        payload.event_time_ns = bpf_evt.event_time_ns;
        hdr.payload_bytes = static_cast<uint32_t>(sizeof(payload));
        if (g_state.sink) g_state.sink(&hdr, &payload);

    }
#endif /* HK_BPF_PROTON_WINE */
    else {
        /* Unknown tag — future BPF program; silently skip. */
    }

    return 0;
}

#ifdef HK_BPF_MEMORY_ACCESS
/* ---- iter/task_vma row consumer ------------------------------------------ */
/*
 * The iterator streams hk_bpf_vma_row records through its seq buffer (NOT the
 * ringbuf). hk_bpf_loader_trigger_vma_scan() reads the iterator fd and hands each
 * complete row to on_ringbuf_sample-style translation. We reuse the ringbuf
 * translation by feeding the raw bytes through the same per-tag arm; here we
 * translate the HK_BPF_VMA_ROW directly to keep the seq read path self-contained.
 */
static void emit_vma_row(const HkBpfVmaRow *bpf_evt)
{
    hk_event_header hdr {};
    hdr.version       = HK_EVENT_SCHEMA_VERSION;
    hdr.reserved      = 0;
    hdr.type          = kEvtVmaDrift;
    hdr.timestamp_ns  = bpf_evt->timestamp_ns;

    HkEvtVmaRow payload {};
    payload.pid      = bpf_evt->pid;
    payload.vm_flags = bpf_evt->vm_flags;
    payload.vm_start = bpf_evt->vm_start;
    payload.vm_end   = bpf_evt->vm_end;
    payload.dev      = bpf_evt->dev;
    payload.inode    = bpf_evt->inode;
    hdr.payload_bytes = static_cast<uint32_t>(sizeof(payload));

    if (g_state.sink)
        g_state.sink(&hdr, &payload);
}
#endif /* HK_BPF_MEMORY_ACCESS */

/* ---- libbpf log callback ------------------------------------------------- */
/*
 * Routes libbpf diagnostic output through fprintf(stderr) rather than the
 * default print-to-stderr path so the format is consistent with other
 * Horkos log output.
 * Reference: https://libbpf.readthedocs.io/en/latest/api.html#c.libbpf_set_print
 */
static int libbpf_print_fn(enum libbpf_print_level level,
                           const char *format,
                           va_list args)
{
    if (level == LIBBPF_DEBUG)
        return 0;   /* suppress debug noise; enable for loader troubleshooting */
    return vfprintf(stderr, format, args);
}

#ifdef HK_BPF_MEMORY_ACCESS
/* ---- Memory-access program set bring-up ---------------------------------- */
/*
 * Opens each memory-access skeleton, repoints its EXTERN hk_ringbuf at the
 * already-created LSM ring map fd, repoints/creates the shared hk_protected map,
 * loads and attaches. The FIRST memory skeleton to load creates hk_protected;
 * the rest reuse it via bpf_map__reuse_fd, mirroring the hk_ringbuf sharing
 * pattern. iter/task_vma is best-effort: a load failure (kernel < 5.13) is
 * logged and signal 80 is disabled, not fatal (impl-plan §8).
 *
 * Returns 0 on success (or partial success with only signal 80 disabled), a
 * negative errno only on a failure that should abort the whole loader. The
 * caller (hk_bpf_loader_start) treats a hard failure as a cleanup trigger.
 */
static int hk_share_ringbuf(struct bpf_map *dst)
{
    return bpf_map__reuse_fd(dst, bpf_map__fd(g_state.lsm_skel->maps.hk_ringbuf));
}

static int hk_share_protected(struct bpf_map *dst)
{
    /* The first memory skeleton's hk_protected becomes the canonical map; we
     * remember its fd on g_state via vm_skel->maps once loaded. For simplicity
     * and to avoid load-order coupling, every memory skeleton that is NOT the
     * canonical owner reuses the canonical fd. The owner is whichever skeleton
     * we load first below (lsm_ptrace). */
    if (g_state.ptrace_skel == nullptr)
        return 0;   /* owner not yet loaded — caller handles ordering */
    int fd = bpf_map__fd(g_state.ptrace_skel->maps.hk_protected);
    if (fd < 0)
        return fd;
    return bpf_map__reuse_fd(dst, fd);
}

static int start_memory_programs(void)
{
    int err = 0;

    /* ptrace (signals 73/81) is the canonical owner of hk_protected: load it
     * first with __open(), share only hk_ringbuf, then __load() so it CREATES
     * hk_protected. Every later skeleton reuses both maps. */
    g_state.ptrace_skel = lsm_ptrace_bpf__open();
    if (!g_state.ptrace_skel) { err = -errno; goto mem_fail; }
    if ((err = hk_share_ringbuf(g_state.ptrace_skel->maps.hk_ringbuf))) goto mem_fail;
    if ((err = lsm_ptrace_bpf__load(g_state.ptrace_skel))) goto mem_fail;
    if ((err = lsm_ptrace_bpf__attach(g_state.ptrace_skel))) goto mem_fail;

    /* fexit process_vm (signal 74) */
    g_state.vm_skel = fexit_process_vm_bpf__open();
    if (!g_state.vm_skel) { err = -errno; goto mem_fail; }
    if ((err = hk_share_ringbuf(g_state.vm_skel->maps.hk_ringbuf))) goto mem_fail;
    if ((err = hk_share_protected(g_state.vm_skel->maps.hk_protected))) goto mem_fail;
    if ((err = fexit_process_vm_bpf__load(g_state.vm_skel))) goto mem_fail;
    if ((err = fexit_process_vm_bpf__attach(g_state.vm_skel))) goto mem_fail;

    /* fentry mem_open (signal 75) */
    g_state.procmem_skel = fentry_proc_mem_bpf__open();
    if (!g_state.procmem_skel) { err = -errno; goto mem_fail; }
    if ((err = hk_share_ringbuf(g_state.procmem_skel->maps.hk_ringbuf))) goto mem_fail;
    if ((err = hk_share_protected(g_state.procmem_skel->maps.hk_protected))) goto mem_fail;
    if ((err = fentry_proc_mem_bpf__load(g_state.procmem_skel))) goto mem_fail;
    if ((err = fentry_proc_mem_bpf__attach(g_state.procmem_skel))) goto mem_fail;

    /* mmap/mprotect (signals 76/79) */
    g_state.mmap_skel = lsm_mmap_mprotect_bpf__open();
    if (!g_state.mmap_skel) { err = -errno; goto mem_fail; }
    if ((err = hk_share_ringbuf(g_state.mmap_skel->maps.hk_ringbuf))) goto mem_fail;
    if ((err = hk_share_protected(g_state.mmap_skel->maps.hk_protected))) goto mem_fail;
    if ((err = lsm_mmap_mprotect_bpf__load(g_state.mmap_skel))) goto mem_fail;
    if ((err = lsm_mmap_mprotect_bpf__attach(g_state.mmap_skel))) goto mem_fail;

    /* memfd_create + bprm exec (signal 77) */
    g_state.memfd_skel = memfd_exec_bpf__open();
    if (!g_state.memfd_skel) { err = -errno; goto mem_fail; }
    if ((err = hk_share_ringbuf(g_state.memfd_skel->maps.hk_ringbuf))) goto mem_fail;
    if ((err = hk_share_protected(g_state.memfd_skel->maps.hk_protected))) goto mem_fail;
    if ((err = memfd_exec_bpf__load(g_state.memfd_skel))) goto mem_fail;
    if ((err = memfd_exec_bpf__attach(g_state.memfd_skel))) goto mem_fail;

    /* devmem (signal 78) — host-wide, still shares hk_ringbuf; no hk_protected use. */
    g_state.devmem_skel = lsm_devmem_bpf__open();
    if (!g_state.devmem_skel) { err = -errno; goto mem_fail; }
    if ((err = hk_share_ringbuf(g_state.devmem_skel->maps.hk_ringbuf))) goto mem_fail;
    if ((err = lsm_devmem_bpf__load(g_state.devmem_skel))) goto mem_fail;
    if ((err = lsm_devmem_bpf__attach(g_state.devmem_skel))) goto mem_fail;

    /* iter/task_vma (signal 80) — BEST EFFORT. A load failure means the runtime
     * kernel lacks the task_vma iterator (< 5.13); disable signal 80 and
     * continue (impl-plan §8). The iterator is NOT auto-attached — it is driven
     * on demand by hk_bpf_loader_trigger_vma_scan(). */
    {
        g_state.vma_skel = iter_task_vma_bpf__open();
        if (!g_state.vma_skel) {
            fprintf(stderr, "hk_loader: iter_task_vma open failed; signal 80 disabled.\n");
        } else if (hk_share_protected(g_state.vma_skel->maps.hk_protected) != 0 ||
                   iter_task_vma_bpf__load(g_state.vma_skel) != 0) {
            fprintf(stderr, "hk_loader: iter_task_vma load failed (kernel < 5.13?); "
                            "signal 80 disabled.\n");
            iter_task_vma_bpf__destroy(g_state.vma_skel);
            g_state.vma_skel = nullptr;
        } else {
            /* bpf_program__attach_iter returns a bpf_link*; libbpf encodes
             * failure as a negative-errno pointer, so use libbpf_get_error to
             * test it before dereferencing (the idiomatic check). */
            struct bpf_link *link =
                bpf_program__attach_iter(g_state.vma_skel->progs.hk_iter_task_vma, nullptr);
            if (link == nullptr || libbpf_get_error(link) != 0) {
                fprintf(stderr, "hk_loader: iter_task_vma attach_iter failed; "
                                "signal 80 disabled.\n");
                iter_task_vma_bpf__destroy(g_state.vma_skel);
                g_state.vma_skel = nullptr;
            } else {
                g_state.vma_link      = link;
                g_state.vma_iter_fd   = bpf_link__fd(link);
                g_state.vma_available = true;
            }
        }
    }

    return 0;

mem_fail:
    fprintf(stderr, "hk_loader: memory-access program set bring-up failed: %s\n",
            std::strerror(err < 0 ? -err : err));
    return err < 0 ? err : -err;
}
#endif /* HK_BPF_MEMORY_ACCESS */

/* ---- Public API ---------------------------------------------------------- */

int hk_bpf_loader_start(HkEventSink sink)
{
    int err = 0;

    libbpf_set_print(libbpf_print_fn);

    g_state.sink      = sink;
    g_state.stop_flag = false;

    /* --- Open and load LSM skeleton --- */
    /*
     * lsm_file_open_bpf__open_and_load() opens the embedded BPF ELF, verifies
     * all programs through the kernel verifier, and creates the maps.
     * Requires kernel ≥ 5.7 (BPF LSM), CONFIG_BPF_LSM=y, and "bpf" listed in
     * the lsm= kernel command-line parameter.
     * Reference: https://docs.kernel.org/bpf/prog_lsm.html
     */
    g_state.lsm_skel = lsm_file_open_bpf__open_and_load();
    if (!g_state.lsm_skel) {
        err = -errno;
        fprintf(stderr, "hk_loader: failed to open+load lsm_file_open skeleton: %s\n",
                std::strerror(-err));
        goto cleanup;
    }

    err = lsm_file_open_bpf__attach(g_state.lsm_skel);
    if (err) {
        fprintf(stderr, "hk_loader: failed to attach lsm_file_open programs: %s\n",
                std::strerror(-err));
        goto cleanup;
    }

    /* --- Open, share map, load tracepoints skeleton --- */
    /*
     * The tracepoints skeleton declares hk_ringbuf as an EXTERN map. Across two
     * independently-opened skeletons libbpf does NOT auto-resolve that — we must
     * open() first, point its hk_ringbuf at the already-created LSM map fd via
     * bpf_map__reuse_fd(), THEN load(). Using __open_and_load() here would create
     * a second, unread ring buffer and silently drop ptrace/exec events.
     * Reference: https://libbpf.readthedocs.io/en/latest/api.html
     */
    g_state.tp_skel = tracepoints_bpf__open();
    if (!g_state.tp_skel) {
        err = -errno;
        fprintf(stderr, "hk_loader: failed to open tracepoints skeleton: %s\n",
                std::strerror(-err));
        goto cleanup;
    }

    err = bpf_map__reuse_fd(g_state.tp_skel->maps.hk_ringbuf,
                            bpf_map__fd(g_state.lsm_skel->maps.hk_ringbuf));
    if (err) {
        fprintf(stderr, "hk_loader: failed to share hk_ringbuf with tracepoints: %s\n",
                std::strerror(-err));
        goto cleanup;
    }

    err = tracepoints_bpf__load(g_state.tp_skel);
    if (err) {
        fprintf(stderr, "hk_loader: failed to load tracepoints skeleton: %s\n",
                std::strerror(-err));
        goto cleanup;
    }

    err = tracepoints_bpf__attach(g_state.tp_skel);
    if (err) {
        fprintf(stderr, "hk_loader: failed to attach tracepoints programs: %s\n",
                std::strerror(-err));
        goto cleanup;
    }

#ifdef HK_BPF_MEMORY_ACCESS
    /* --- Memory-access program set (signals 73-81) --- */
    err = start_memory_programs();
    if (err) {
        /* Hard failure (not the soft signal-80 disable, which returns 0). */
        goto cleanup;
    }
#endif

    /* --- Create ring buffer consumer --- */
    /*
     * ring_buffer__new() takes the map fd from the LSM skeleton's hk_ringbuf
     * map.  Because both skeletons share the same underlying map (extern map
     * resolution), all BPF programs write to this single fd.
     *
     * The callback on_ringbuf_sample is invoked synchronously from within
     * ring_buffer__poll().
     * Reference: https://libbpf.readthedocs.io/en/latest/api.html#c.ring_buffer__new
     */
    {
        int map_fd = bpf_map__fd(g_state.lsm_skel->maps.hk_ringbuf);
        if (map_fd < 0) {
            err = map_fd;
            fprintf(stderr, "hk_loader: could not get hk_ringbuf fd: %s\n",
                    std::strerror(-err));
            goto cleanup;
        }
        g_state.ringbuf = ring_buffer__new(map_fd, on_ringbuf_sample,
                                           nullptr, nullptr);
        if (!g_state.ringbuf) {
            err = -errno;
            fprintf(stderr, "hk_loader: ring_buffer__new failed: %s\n",
                    std::strerror(-err));
            goto cleanup;
        }
    }

    return 0;

cleanup:
    hk_bpf_loader_stop();
    return err;
}

void hk_bpf_loader_poll(int timeout_ms)
{
    /*
     * ring_buffer__poll() drains all pending records (calling on_ringbuf_sample
     * per record) and blocks up to timeout_ms waiting for new ones via epoll.
     * Returns the number of records consumed, or a negative errno on error.
     *
     * THREADING CONTRACT: poll() and stop() are NOT thread-safe against each
     * other (ring_buffer__free races ring_buffer__poll). Run the loop and stop()
     * on the SAME thread, with a finite timeout so the loop can observe the flag:
     *   while (!hk_bpf_loader_should_stop()) hk_bpf_loader_poll(100);
     *   hk_bpf_loader_stop();
     * Once stop has been requested, poll() is a no-op so a late call is safe.
     * Reference: https://libbpf.readthedocs.io/en/latest/api.html#c.ring_buffer__poll
     */
    if (g_state.stop_flag || !g_state.ringbuf) return;

    int consumed = ring_buffer__poll(g_state.ringbuf, timeout_ms);
    if (consumed < 0 && consumed != -EINTR) {
        fprintf(stderr, "hk_loader: ring_buffer__poll error: %s\n",
                std::strerror(-consumed));
    }
}

bool hk_bpf_loader_should_stop(void)
{
    return g_state.stop_flag;
}

void hk_bpf_loader_stop(void)
{
    /* Must run on the same thread as the poll loop (see poll()'s contract):
     * setting the flag first guarantees no concurrent poll() is mid-epoll on
     * the ring buffer we are about to free. */
    g_state.stop_flag = true;

    if (g_state.ringbuf) {
        ring_buffer__free(g_state.ringbuf);
        g_state.ringbuf = nullptr;
    }

#ifdef HK_BPF_MEMORY_ACCESS
    /* Tear down the memory-access set in REVERSE load order. Skeletons that reuse
     * the canonical hk_protected fd must be destroyed before the owner
     * (ptrace_skel) so the shared fd outlives its borrowers. */
    if (g_state.vma_link) {
        bpf_link__destroy(g_state.vma_link);
        g_state.vma_link = nullptr;
    }
    g_state.vma_iter_fd   = -1;
    g_state.vma_available = false;
    if (g_state.vma_skel)   { iter_task_vma_bpf__destroy(g_state.vma_skel);     g_state.vma_skel = nullptr; }
    if (g_state.devmem_skel){ lsm_devmem_bpf__destroy(g_state.devmem_skel);     g_state.devmem_skel = nullptr; }
    if (g_state.memfd_skel) { memfd_exec_bpf__destroy(g_state.memfd_skel);      g_state.memfd_skel = nullptr; }
    if (g_state.mmap_skel)  { lsm_mmap_mprotect_bpf__destroy(g_state.mmap_skel);g_state.mmap_skel = nullptr; }
    if (g_state.procmem_skel){ fentry_proc_mem_bpf__destroy(g_state.procmem_skel);g_state.procmem_skel = nullptr; }
    if (g_state.vm_skel)    { fexit_process_vm_bpf__destroy(g_state.vm_skel);   g_state.vm_skel = nullptr; }
    if (g_state.ptrace_skel){ lsm_ptrace_bpf__destroy(g_state.ptrace_skel);     g_state.ptrace_skel = nullptr; }
    g_state.memfd_join.clear();
#endif

    if (g_state.tp_skel) {
        tracepoints_bpf__destroy(g_state.tp_skel);
        g_state.tp_skel = nullptr;
    }
    if (g_state.lsm_skel) {
        lsm_file_open_bpf__destroy(g_state.lsm_skel);
        g_state.lsm_skel = nullptr;
    }
}

int hk_bpf_loader_protected_map_fd(void)
{
#ifdef HK_BPF_MEMORY_ACCESS
    if (g_state.ptrace_skel == nullptr)
        return -ENODEV;
    return bpf_map__fd(g_state.ptrace_skel->maps.hk_protected);
#else
    return -ENOTSUP;
#endif
}

int hk_bpf_loader_trigger_vma_scan(void)
{
#ifdef HK_BPF_MEMORY_ACCESS
    if (!g_state.vma_available || g_state.vma_iter_fd < 0)
        return 0;   /* signal 80 unavailable (kernel < 5.13) — graceful no-op */

    /* Reading the iterator fd runs the iter/task_vma program once across all
     * tasks; each protected VM_EXEC VMA streams a HkBpfVmaRow into the seq
     * buffer. We read the stream in record-sized chunks and translate each row.
     * The read returns 0 at end-of-iteration. */
    int rows = 0;
    char buf[sizeof(HkBpfVmaRow) * 64];
    for (;;) {
        ssize_t n = read(g_state.vma_iter_fd, buf, sizeof(buf));
        if (n < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN) break;
            return -errno;
        }
        if (n == 0)
            break;   /* iteration complete */

        /* The seq stream is a byte stream of back-to-back fixed-size rows. A
         * short final chunk that does not align to a whole row is dropped (the
         * iterator framework writes whole rows; a partial tail indicates the
         * 64-row buffer split a row, which the next read continues — but since
         * we sized buf to a row multiple and rows are fixed, n is always a row
         * multiple here). */
        size_t off = 0;
        while (off + sizeof(HkBpfVmaRow) <= static_cast<size_t>(n)) {
            HkBpfVmaRow row {};
            std::memcpy(&row, buf + off, sizeof(row));
            if (row.event_tag == kBpfTagVmaRow &&
                row.schema_version == kMemorySchemaVersion) {
                emit_vma_row(&row);
                ++rows;
            }
            off += sizeof(HkBpfVmaRow);
        }
    }
    return rows;
#else
    return 0;
#endif
}
