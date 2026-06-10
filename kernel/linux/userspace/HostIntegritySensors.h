/*
 * kernel/linux/userspace/HostIntegritySensors.h
 * Role: Orchestration interface + provisional wire payloads for the Linux
 *       kernel/module-trust audit sensors (signals 91-99). Declares the audit
 *       aggregator (owns a timer thread, drives each sensor on its cadence and
 *       forwards events through the shared HkEventSink) and the per-signal
 *       payload structs. Does NOT poll the BPF ring buffer — that stays in
 *       Loader.cpp; this aggregator only runs the periodic procfs/sysfs/debugfs
 *       auditors (91/92/93/94/95-userspace/96/97).
 * Target platform: Linux userspace (guardrail #4 — no BPF/kernel headers).
 * Interface: reuses HkEventSink unchanged from Loader.h (guardrail #10 spirit:
 *            the emission contract is stable; these sensors are new backends
 *            behind it). Declares HkHostSensorFn, hk_host_integrity_start/stop,
 *            and the hk_event_* payload mirrors.
 *
 * HK-TODO(schema): the event-type discriminants (HK_EVENT_KSYM_DRIFT=5 ..
 * HK_EVENT_SENSOR_UNAVAILABLE=14) and the payload structs below are owned by the
 * Schema phase and are NOT yet in the frozen sdk/include/horkos/event_schema.h
 * (it is still HK_EVENT_SCHEMA_VERSION=2, enum tops out at HK_EVENT_HANDLE_OPEN
 * =4). They are mirrored here as provisional locals (same pattern as
 * Loader.cpp's memory-access mirrors) so the emit path is ready when Schema
 * lands. NOTE values 5-14 collide pre-Schema with the memory-access and Windows
 * vm-access provisional discriminants — Schema assigns the final distinct values;
 * consumers must dispatch by the resolved type once it lands, not by these
 * provisional numbers. Sizes are pinned with static_assert to the plan's
 * documented byte counts so a future header diff is caught.
 */

#pragma once

#include <cstdint>
#include <string>

#include "Loader.h"      /* HkEventSink — reused unchanged */
#include "SymbolMap.h"

namespace horkos::modint {

/* ---- Provisional event-type discriminants (HK-TODO(schema)) ----------------
 * Range 19..28 is free in event_schema.h (types 1-18 are taken):
 *   1..4  = core events; 5..13 = Windows mem-injection family (v3 schema);
 *   14..17 = HV/virtualization family (v4 schema); 18 = process-create-ex (v5).
 * The Rust server decoder in telemetry/src/kernel_events.rs mirrors these
 * values and must be updated in lockstep with any change here. */
constexpr uint32_t kEvtKsymDrift          = 19u;
constexpr uint32_t kEvtModuleViewDiff     = 20u;
constexpr uint32_t kEvtFtraceHook         = 21u;
constexpr uint32_t kEvtKprobeSensitive    = 22u;
constexpr uint32_t kEvtModuleDiskDrift    = 23u;
constexpr uint32_t kEvtKernelPosture      = 24u;
constexpr uint32_t kEvtForeignBpf         = 25u;
constexpr uint32_t kEvtDevmemAccess       = 26u;
constexpr uint32_t kEvtMsrWriteSensitive  = 27u;
constexpr uint32_t kEvtSensorUnavailable  = 28u;

/* ---- Signal ids used in SENSOR_UNAVAILABLE.signal_id (catalog numbers) ----- */
constexpr uint32_t kSignalKsymDrift     = 91u;
constexpr uint32_t kSignalModuleView    = 92u;
constexpr uint32_t kSignalFtrace        = 93u;
constexpr uint32_t kSignalKprobe        = 94u;
constexpr uint32_t kSignalModuleDisk    = 95u;
constexpr uint32_t kSignalPosture       = 96u;
constexpr uint32_t kSignalForeignBpf    = 97u;

/* ---- Reason / flag enums (wire contract; append only) --------------------- */
enum HkKsymDriftReason : uint32_t {
    HK_KSYM_OOB       = 0,   /* resolved address outside every known text range */
    HK_KSYM_COLLISION = 1,   /* two distinct symbols resolve to the same address */
    HK_KSYM_SHADOW    = 2,   /* sensitive symbol resolves into a module, not core */
};

enum HkModuleViewBit : uint32_t {
    HK_MV_PROCMODULES = 0x1u,   /* present in /proc/modules            */
    HK_MV_SYSFS       = 0x2u,   /* present under /sys/module           */
    HK_MV_BPF_OR_LKM  = 0x4u,   /* present in the bpf-iter / LKM view  */
};

enum HkKprobeFlag : uint32_t {
    HK_KP_OPTIMIZED  = 0x1u,
    HK_KP_DISABLED   = 0x2u,
    HK_KP_MODULELESS = 0x4u,    /* probe owner is not an attributable module */
};

enum HkModuleDiskReason : uint32_t {
    HK_MD_BUILDID_MISMATCH = 0,
    HK_MD_CRC_MISMATCH     = 1,
    HK_MD_NO_DISK_KO       = 2,
};

/* ---- Provisional payload mirrors (HK-TODO(schema)) ------------------------- */
/* No strings in payloads — names are hashed to a u64 (name_hash); the raw name
 * is carried out-of-band keyed by hash. Symbol/function identities use the
 * interned HkSensitiveSymbol index. */

struct HkEvtKsymDrift {           /* 32 bytes */
    uint64_t resolved_addr;
    uint64_t expected_lo;
    uint64_t expected_hi;
    uint32_t reason;              /* HkKsymDriftReason */
    uint32_t symbol_id;          /* interned HkSensitiveSymbol */
};
static_assert(sizeof(HkEvtKsymDrift) == 32, "hk_event_ksym_drift must be 32 bytes");

struct HkEvtModuleViewDiff {      /* 16 bytes */
    uint64_t name_hash;
    uint32_t present_mask;       /* HkModuleViewBit OR */
    uint32_t module_state;       /* 0=live,1=coming,2=going (debounced out) */
};
static_assert(sizeof(HkEvtModuleViewDiff) == 16,
              "hk_event_module_view_diff must be 16 bytes");

struct HkEvtFtraceHook {          /* 24 bytes */
    uint64_t func_addr;
    uint64_t ops_owner_addr;
    uint32_t owner_attributed;   /* 0/1 */
    uint32_t func_id;            /* interned HkSensitiveSymbol */
};
static_assert(sizeof(HkEvtFtraceHook) == 24, "hk_event_ftrace_hook must be 24 bytes");

struct HkEvtKprobeSensitive {     /* 24 bytes */
    uint64_t probe_addr;
    uint32_t symbol_id;          /* interned HkSensitiveSymbol */
    uint32_t flags;              /* HkKprobeFlag OR */
    uint32_t owner_signed;       /* 0/1; 1 = owning module is signed/allowlisted */
    uint32_t reserved;
};
static_assert(sizeof(HkEvtKprobeSensitive) == 24,
              "hk_event_kprobe_sensitive must be 24 bytes");

struct HkEvtModuleDiskDrift {     /* 16 bytes */
    uint64_t name_hash;
    uint32_t reason;             /* HkModuleDiskReason */
    uint32_t reserved;
};
static_assert(sizeof(HkEvtModuleDiskDrift) == 16,
              "hk_event_module_disk_drift must be 16 bytes");

struct HkEvtKernelPosture {       /* 16 bytes */
    uint32_t lockdown_level;     /* 0=none,1=integrity,2=confidentiality,0xFFFFFFFF=unknown */
    uint32_t sig_enforce;        /* 0/1/0xFFFFFFFF unknown */
    uint32_t secure_boot;        /* 0/1/0xFFFFFFFF unknown */
    uint32_t taint_flags;        /* /proc/sys/kernel/tainted bitmask */
};
static_assert(sizeof(HkEvtKernelPosture) == 16,
              "hk_event_kernel_posture must be 16 bytes");

struct HkEvtForeignBpf {          /* 16 bytes */
    uint64_t prog_tag_hash;
    uint32_t prog_id;
    uint32_t prog_type;
};
static_assert(sizeof(HkEvtForeignBpf) == 16, "hk_event_foreign_bpf must be 16 bytes");

struct HkEvtSensorUnavailable {   /* 8 bytes */
    uint32_t signal_id;          /* catalog number 91..99 */
    uint32_t errno_value;        /* the errno that gated the source read */
};
static_assert(sizeof(HkEvtSensorUnavailable) == 8,
              "hk_event_sensor_unavailable must be 8 bytes");

/* Non-reversible 64-bit digest of a module/file name (FNV-1a). The raw name is
 * never put in the event plane (PII minimisation, §9). */
uint64_t HkNameHash(const std::string& name);

/* Build and emit one event through the sink with a populated header. `type` is
 * one of the kEvt* discriminants; `payload`/`size` describe the payload struct.
 * Centralised so every sensor stamps the header identically. */
void HkEmit(HkEventSink sink, uint32_t type, const void* payload, uint32_t size);

/* Emit a SENSOR_UNAVAILABLE coverage-gap event for `signal_id` with `err`. */
void HkEmitUnavailable(HkEventSink sink, uint32_t signal_id, int err);

/* ---- Sensor function shape + aggregator lifecycle ------------------------- */
/* Each sensor returns 0 on a completed cycle (even if it emitted "unavailable");
 * negative errno only on an unrecoverable internal error. Sensors never block. */
typedef int (*HkHostSensorFn)(const HkSymbolMap* map, HkEventSink sink);

int  hk_host_integrity_start(HkEventSink sink);   /* spawns the timer thread */
void hk_host_integrity_stop(void);                /* stop on the owning thread */

}  // namespace horkos::modint
