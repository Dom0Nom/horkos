/*
 * Role: Wire-format source of truth for the Windows usermode render/overlay
 *       sensor findings (catalog signals 46-54). Defines the verdict enums,
 *       window-style bitmask, and the fixed-size numeric core record
 *       (hk_render_finding). This is a SEPARATE report plane from the kernel
 *       event schema (event_schema.h): render findings carry variable-length
 *       strings (module path, Authenticode signer subject, window class) that do
 *       NOT fit the 16-byte HK_EVENT_PAYLOAD_MAX kernel ring record, so they ride
 *       a JSON envelope keyed by record index — never the HK_IOCTL_DRAIN_EVENTS
 *       path. Any field addition bumps HK_RENDER_SCHEMA_VERSION.
 * Target platforms: all (plain C99, no platform headers; reuses HK_STATIC_ASSERT
 *       and <stdint.h> from event_schema.h so it stays kernel-includable in
 *       principle, though no kernel TU includes it — guardrail #4).
 * Interface: mirrored by server/telemetry/src/render_hook.rs; included by the SDK
 *       usermode render-sensor TUs under sdk/src/backends/win/ only.
 */

#pragma once

#include <stdint.h>

/* HK_STATIC_ASSERT (and the <stdint.h> width types) come from the existing event
 * schema header so the static size pin uses the same portable macro. No event
 * types are pulled into the render plane; the two planes stay independent. */
#include "horkos/event_schema.h"

/* Render-plane schema version. Independent of HK_EVENT_SCHEMA_VERSION; the server
 * mirror (RENDER_SCHEMA_VERSION) tracks this in lockstep. */
#define HK_RENDER_SCHEMA_VERSION 1u

/* Catalog signal id, stable. The numeric value IS the catalog signal number so a
 * finding is self-describing on the wire. */
typedef enum hk_render_signal {
    HK_RENDER_SIG_VTABLE_PROVENANCE  = 46,
    HK_RENDER_SIG_PROLOGUE_RECONCILE = 47,
    HK_RENDER_SIG_FRAMESTATS         = 48,
    HK_RENDER_SIG_LAYERED_WINDOW     = 49,
    HK_RENDER_SIG_DWM_THUMBNAIL      = 50,
    HK_RENDER_SIG_MAGNIFIER          = 51,
    HK_RENDER_SIG_HOOKDLL            = 52,
    HK_RENDER_SIG_GDI_PRESSURE       = 53,
    HK_RENDER_SIG_VULKAN_LAYER       = 54
} hk_render_signal;

/* Target classification for the provenance signals (46/47/52/54). The client only
 * RESOLVES and reports the verdict + signer subject; the allow-list trust decision
 * is server-side signed-rule plumbing (catalog: "the server alone decides; never
 * ban on presence of a hook"). */
typedef enum hk_provenance_verdict {
    HK_PROV_IMAGE_SIGNED_ALLOWLISTED = 0, /* target in a signed allow-listed module */
    HK_PROV_IMAGE_SIGNED_FOREIGN     = 1, /* image-backed, signed, not allow-listed  */
    HK_PROV_IMAGE_UNSIGNED           = 2, /* image-backed, no valid Authenticode      */
    HK_PROV_PRIVATE_RX               = 3, /* MEM_PRIVATE / unbacked executable target */
    HK_PROV_UNRESOLVED               = 4  /* VirtualQuery failed / sensor inconclusive */
} hk_provenance_verdict;

/* Window-style bitmask (signals 49/51). Mirrors the GWL_EXSTYLE bits and DWM cloak
 * state we record; not raw window handles. */
#define HK_WSTYLE_LAYERED      0x01u
#define HK_WSTYLE_TRANSPARENT  0x02u
#define HK_WSTYLE_TOPMOST      0x04u
#define HK_WSTYLE_NOACTIVATE   0x08u
#define HK_WSTYLE_CLOAKED      0x10u  /* DWMWA_CLOAKED is true */
#define HK_WSTYLE_CLICKTHROUGH 0x20u  /* per-pixel-alpha + transparent (pass-through) */

/* Fixed-size numeric core of one finding. The variable strings (module_path,
 * signer_subject, window_class) travel in the JSON envelope keyed by record index,
 * NEVER inline, so this struct stays fixed-size and the on-disk paths are not
 * length-bounded. Every "else 0" field is zero when the emitting signal does not
 * populate it. */
typedef struct hk_render_finding {
    uint32_t schema_version;   /* HK_RENDER_SCHEMA_VERSION at emit. */
    uint32_t signal;           /* hk_render_signal. */
    uint32_t verdict;          /* hk_provenance_verdict, or 0 when N/A. */
    uint32_t style_bits;       /* HK_WSTYLE_* (signals 49/51), else 0. */
    uint32_t owning_pid;       /* foreign PID for window/footprint signals, else 0. */
    uint32_t slot_index;       /* vtable slot (46) or export ordinal (47), else 0. */
    uint64_t target_addr;      /* resolved vtable/prologue target VA (46/47), else 0. */
    uint64_t region_hash;      /* divergent-region hash (47) / cadence fingerprint, else 0. */
    int64_t  cadence_drift_ns; /* signed frame-stat/cadence drift (48/50/53), else 0. */
} hk_render_finding;

/* 6 x uint32 (24) + 3 x 64-bit (24) = 48 bytes, no tail padding (the 64-bit
 * members are already 8-byte aligned after the six 4-byte members). */
HK_STATIC_ASSERT(sizeof(hk_render_finding) == 48,
    "hk_render_finding size mismatch — update server/telemetry/src/render_hook.rs "
    "RenderFinding numeric fields in lockstep");
