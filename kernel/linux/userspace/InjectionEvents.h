/*
 * Role: Provisional userspace-side event constants + fixed payload structs for
 *       the Linux injection correlators (signals 82-90), plus the BPF-side event
 *       struct mirrors the correlators consume. These mirror the schema
 *       (HK_EVENT_DSO_PROVENANCE=5 .. HK_EVENT_TEXT_PATCH=12 and the three
 *       16-byte payloads hk_event_dso_anomaly / hk_event_got_anomaly /
 *       hk_event_loader_integrity).
 * Target platform: Linux userspace.
 * Interface: shared by all eight correlators.
 *
 * HK-TODO(schema): the event-type discriminants (5..12) and the three payload
 * structs are owned by the Schema phase and are NOT yet present in the frozen
 * sdk/include/horkos/event_schema.h (still HK_EVENT_SCHEMA_VERSION=2, enum tops
 * out at HK_EVENT_HANDLE_OPEN=4). The values 5..12 collide pre-Schema with the
 * Windows vm_access / thread-origin provisional discriminants — the Schema phase
 * assigns the final distinct values. Until it lands these are local provisional
 * consts so the correlator emit path is ready; the build-id PREFIX rides the
 * fixed record while the full soname/build-id string travels out-of-band on the
 * userspace->server JSON plane (JSON side-channel, option B).
 */

#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace horkos::inject {

/* ---- Provisional event-type discriminants (HK-TODO(schema)) -------------- */
inline constexpr uint32_t kEvtDsoProvenance   = 5;   /* signal 82 */
inline constexpr uint32_t kEvtGotAnomaly      = 6;   /* signal 83 */
inline constexpr uint32_t kEvtInterpMismatch  = 7;   /* signal 84 */
inline constexpr uint32_t kEvtPreloadAnomaly  = 8;   /* signals 85, 89 */
inline constexpr uint32_t kEvtDlopenBacking   = 9;   /* signal 86 */
inline constexpr uint32_t kEvtLoadorderInvert = 10;  /* signal 87 */
inline constexpr uint32_t kEvtRdebugAnomaly   = 11;  /* signal 88 */
inline constexpr uint32_t kEvtTextPatch       = 12;  /* signal 90 */

/* ---- Fixed payload flag bits -------------------------------------------- */
/* hk_event_dso_anomaly.flags (signals 82/87). */
inline constexpr uint32_t HK_DSO_FLAG_NO_DT_NEEDED   = 0x1u;
inline constexpr uint32_t HK_DSO_FLAG_ORDER_INVERT   = 0x2u;
inline constexpr uint32_t HK_DSO_FLAG_OUTSIDE_ALLOW  = 0x4u;
inline constexpr uint32_t HK_DSO_FLAG_MEMFD_DELETED  = 0x8u;

/* hk_event_got_anomaly.got_flags (signal 83). */
inline constexpr uint32_t HK_GOT_FLAG_RWX_TARGET  = 0x1u;
inline constexpr uint32_t HK_GOT_FLAG_ANON_TARGET = 0x2u;
inline constexpr uint32_t HK_GOT_FLAG_FOREIGN_DSO = 0x4u;

/* hk_event_loader_integrity.kind_flags (signals 84/85/88/90/89). */
inline constexpr uint32_t HK_LI_INTERP_MISMATCH   = 0x01u;
inline constexpr uint32_t HK_LI_PRELOAD_TRANSIENT = 0x02u;
inline constexpr uint32_t HK_LI_RDEBUG_FOREIGN    = 0x04u;
inline constexpr uint32_t HK_LI_RELRO_WRITABLE    = 0x08u;
inline constexpr uint32_t HK_LI_TEXT_COW_BROKEN   = 0x10u;
inline constexpr uint32_t HK_LI_LD_AUDIT_ACTIVE   = 0x20u;

/* ---- Fixed 16-byte payload structs -------------------------------------- */
struct DsoAnomaly {        /* signals 82/87 */
    uint32_t pid;
    uint32_t flags;        /* HK_DSO_FLAG_* */
    uint64_t buildid_prefix;
};

struct GotAnomaly {        /* signal 83 */
    uint32_t pid;
    uint32_t got_flags;    /* HK_GOT_FLAG_* */
    uint64_t slot_target;
};

struct LoaderIntegrity {   /* signals 84/85/88/90/89 */
    uint32_t pid;
    uint32_t kind_flags;   /* HK_LI_* */
    uint64_t detail;       /* offset / r_brk VA / dirty-page VA per kind */
};

static_assert(sizeof(DsoAnomaly) == 16, "DsoAnomaly must be 16 bytes");
static_assert(sizeof(GotAnomaly) == 16, "GotAnomaly must be 16 bytes");
static_assert(sizeof(LoaderIntegrity) == 16, "LoaderIntegrity must be 16 bytes");

/* ---- Variable-length JSON side-channel record (option B) ---
 * The fixed payloads above ride the C record; the full soname/path/build-id
 * strings travel out-of-band to the server on the userspace->server JSON plane.
 * This struct is the in-process hand-off the correlators fill; the loader/JSON
 * forwarder serializes it. */
struct InjectionFinding {
    uint32_t event_type = 0;     /* one of kEvt* above */
    uint32_t pid = 0;
    uint32_t flags = 0;          /* the matching fixed-payload flags word */
    uint64_t detail = 0;         /* slot_target / detail / buildid_prefix */
    std::string soname_or_path;  /* full soname or resolved path (JSON-only) */
    std::vector<uint8_t> build_id;  /* full NT_GNU_BUILD_ID (JSON-only) */
};

/* Sink the correlators call for each finding. Mirrors HkEventSink's "must not
 * block" contract. */
using FindingSink = void (*)(const InjectionFinding& finding, void* user);

}  // namespace horkos::inject
