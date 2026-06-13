/*
 * Role: Wire-format source of truth for the AUTHORITATIVE game-state snapshot IPC
 *       plane (server-side behavioral-gamestate domain, catalog signals 172-180).
 *       This is a THIRD wire plane, distinct from both event_schema.h (the C99
 *       kernel-event records that ride the IOCTL ring) and the HTTP/JSON
 *       TickPayload (client-reported per-tick telemetry). The game-server process
 *       publishes fixed-size HkSnapshotRecord frames into a shared-memory ring;
 *       Horkos telemetry attaches the ring read-only and replays the frames. The
 *       frame carries the server-KNOWN truth the client is never told: authoritative
 *       entity transforms, the local view basis, server PVS/BVH visibility results,
 *       the authoritative audio-path graph, dynamic occluder volumes, the per-shot
 *       recoil RNG vector, and the server-random objective seed. Every analyzer's
 *       discriminator is "client-reported behavior vs. this server-only ground truth".
 *       This header declares NO verdict and NO ban authority — it is read-only
 *       evidence; ban fusion stays in ban-engine.
 * Target platforms: server (game-server producer + Horkos telemetry consumer). Plain
 *       C99, no platform headers, no compiler extensions, so a non-Rust game server
 *       can produce these frames and a C99/C++ build can consume them. NOT a kernel
 *       TU header (guardrail #4) — it never rides the kernel event/IOCTL plane.
 * Interface: mirrored field-for-field by the `#[repr(C)]` structs in
 *       server/telemetry/src/snapshot/ipc.rs (with matching size asserts). The
 *       POSIX/Win32 shared-memory attach is isolated in
 *       server/telemetry/src/snapshot/backends/{posix,win}.rs (guardrail #1).
 */

#pragma once

#include <stdint.h>

/* Pulls HK_STATIC_ASSERT (and <stdint.h> width types). The snapshot plane reuses
 * only the portable compile-time-assert macro from the event schema; it does NOT
 * reuse any kernel event type (this header is never included by a kernel TU). */
#include "horkos/event_schema.h"

/* Snapshot IPC plane schema version. Independent of HK_EVENT_SCHEMA_VERSION and the
 * JSON TickPayload SCHEMA_VERSION; the Rust mirror tracks this in lockstep. Every
 * additive field bumps it; no field renames; deprecated fields stay reserved. */
#define HK_SNAPSHOT_SCHEMA_VERSION 1u

/* Maximum actors per snapshot frame. Bounds the fixed-size head so the ring slot is
 * a compile-time constant. The consumer MUST reject entity_count > this maximum
 * (torn/forged frame) rather than index past the array (shm trust boundary). */
#define HK_SNAP_MAX_ENTITIES 256u

/* Per-entity bitset word count: one bit per entity, 32 entities per u32 word. */
#define HK_SNAP_BITSET_WORDS (HK_SNAP_MAX_ENTITIES / 32u) /* == 8 */

/* ---- Entity flags (HkEntityState.flags) ----------------------------------- */
#define HK_ENT_ALIVE 0x00000001u /* actor is alive this tick. */
#define HK_ENT_LOCAL 0x00000002u /* actor is the local player whose client we judge. */
#define HK_ENT_TEAM  0x00000004u /* actor is on the local player's team (callout-explainable). */

typedef struct HkVec3 { float x, y, z; } HkVec3; /* 12 bytes, 4-byte align. */
HK_STATIC_ASSERT(sizeof(HkVec3) == 12, "HkVec3 size mismatch — update snapshot/ipc.rs HkVec3");

/* -------------------------------------------------------------------------
 * One actor this tick. Authoritative server-side transform; the client is never
 * told the occluded actors' positions, which is the whole basis of the domain.
 * ------------------------------------------------------------------------- */
typedef struct HkEntityState {
    uint64_t entity_id;  /* stable per-match actor id. */
    HkVec3   position;   /* authoritative world position. */
    HkVec3   velocity;   /* authoritative world velocity. */
    uint32_t flags;      /* HK_ENT_* bitmask. */
    uint32_t _pad;       /* must be zero; keeps the struct a clean 40 bytes. */
} HkEntityState;
/* Layout: entity_id(8) at 0; position(12) at 8; velocity(12) at 20; flags(4) at 32;
 * _pad(4) at 36 = 40. Max align is 8 (entity_id), 40 % 8 == 0, no tail pad.
 * NOTE: an earlier draft asserted == 48; that overcounted. The frozen size is 40.
 * The Rust mirror MUST use 40. */
HK_STATIC_ASSERT(sizeof(HkEntityState) == 40,
    "HkEntityState size mismatch — update snapshot/ipc.rs HkEntityState in lockstep "
    "(correct size is 40)");

/* -------------------------------------------------------------------------
 * One authoritative snapshot frame. Fixed-size head; the variable-length dynamic
 * occluder trailer (HkOccluderVolume[occluder_count]) follows in the ring slot,
 * addressed separately by occluder_count so the head stays a constant size.
 * ------------------------------------------------------------------------- */
typedef struct HkSnapshotRecord {
    uint32_t schema_version;            /* == HK_SNAPSHOT_SCHEMA_VERSION; mismatch -> reject. */
    uint32_t entity_count;             /* valid entities[]; MUST be <= HK_SNAP_MAX_ENTITIES. */
    uint64_t tick;                     /* server simulation tick. */
    uint64_t mono_ns;                  /* clock_gettime(CLOCK_MONOTONIC) at sim (174/178). */
    uint64_t local_player_id;          /* entity_id of the judged local player. */
    HkVec3   cam_origin;               /* local view origin (173/177 frustum reconstruction). */
    HkVec3   cam_forward;              /* local view forward (unit). */
    HkVec3   cam_up;                   /* local view up (unit). */
    float    cam_fov_rad;              /* local horizontal FOV (radians). */
    uint32_t visibility_bits[HK_SNAP_BITSET_WORDS]; /* per-entity server PVS/BVH LoS to local. */
    uint32_t audiopath_bits[HK_SNAP_BITSET_WORDS];  /* per-entity authoritative audio path exists. */
    uint32_t occluder_count;           /* dynamic smoke/particle volumes in the trailer (175). */
    HkVec3   recoil_rng_vec;           /* per-shot authoritative recoil incl. random component (180). */
    uint64_t objective_seed;           /* server-random spawn/objective seed this match (176). */
    HkEntityState entities[HK_SNAP_MAX_ENTITIES];
} HkSnapshotRecord;
/* Frozen layout (see the offset audit in snapshot/ipc.rs which mirrors this):
 *   schema_version 0, entity_count 4, tick 8, mono_ns 16, local_player_id 24,
 *   cam_origin 32, cam_forward 44, cam_up 56, cam_fov_rad 68,
 *   visibility_bits 72 (32B), audiopath_bits 104 (32B), occluder_count 136,
 *   recoil_rng_vec 140, objective_seed 152 (8-aligned, no hidden pad before it),
 *   entities[] 160. Head = 160 bytes; entities = 256*40 = 10240; total = 10400.
 * Max align is 8; 10400 % 8 == 0, no tail pad. */
HK_STATIC_ASSERT(sizeof(HkSnapshotRecord) == 160u + HK_SNAP_MAX_ENTITIES * 40u,
    "HkSnapshotRecord size mismatch — update snapshot/ipc.rs HkSnapshotRecord in lockstep "
    "(frozen total is 10400)");

/* -------------------------------------------------------------------------
 * Dynamic occluder volume (catalog 175). Variable-length trailer addressed by
 * HkSnapshotRecord.occluder_count, kept OUT of the fixed head to bound frame size.
 * An axis-aligned bounding box (min/max corners) plus the tick window it occludes.
 * The consumer MUST bound occluder_count against the ring-slot capacity before
 * walking the trailer (shm trust boundary).
 * ------------------------------------------------------------------------- */
typedef struct HkOccluderVolume {
    HkVec3   aabb_min;     /* AABB minimum corner (world). */
    HkVec3   aabb_max;     /* AABB maximum corner (world). */
    uint64_t born_tick;    /* tick the volume started occluding. */
    uint64_t expire_tick;  /* tick the volume stops occluding (exclusive). */
} HkOccluderVolume;
/* Layout: aabb_min(12) 0; aabb_max(12) 12; born_tick(8) at align 8 -> 24; expire_tick(8) 32 = 40.
 * Max align 8, 40 % 8 == 0, no tail pad. */
HK_STATIC_ASSERT(sizeof(HkOccluderVolume) == 40,
    "HkOccluderVolume size mismatch — update snapshot/ipc.rs HkOccluderVolume in lockstep");

/* -------------------------------------------------------------------------
 * Shared-memory ring transport (the publish/sequence handshake that was the
 * HK-UNCERTAIN(ipc-contract) gap). This is HORKOS-OWNED protocol, not a
 * proprietary engine API: a game server links this header and publishes frames;
 * Horkos telemetry attaches the same shm object read-only.
 *
 * Single-producer (the game server), single-consumer (the telemetry reader).
 * The ring is a header followed by `slot_count` fixed-stride slots. Each slot
 * begins with a u64 SEQLOCK word, then the slot payload (one HkSnapshotRecord
 * head + its HkOccluderVolume[occluder_count] trailer, both within the stride).
 *
 * Publish protocol (producer, per frame):
 *   slot = ring->write_seq % slot_count;
 *   slot->seq = odd  (write_seq*2+1)   // mark "writing"  (store, then fence)
 *   memcpy(slot->payload, frame, payload_len);
 *   slot->seq = even (write_seq*2+2)   // mark "stable, generation write_seq+1"
 *   ring->write_seq += 1;              // publish (store, release)
 *
 * Read protocol (consumer): track the last consumed write_seq; when the ring's
 * write_seq advances, for each new generation seqlock-read the slot — read seq,
 * copy the payload, re-read seq; accept only if seq is EVEN and unchanged
 * across the copy, else the frame was torn (producer mid-write or lapped) and
 * is skipped, never parsed. parse_slot then re-validates the payload contents.
 * ------------------------------------------------------------------------- */
#define HK_SNAP_RING_MAGIC 0x484B5350u /* 'HKSP' little-endian. */

/* Per-slot seqlock+payload header. The payload (HkSnapshotRecord + occluder
 * trailer) follows in the slot's stride bytes. */
typedef struct HkSnapshotSlotHeader {
    uint64_t seq;          /* seqlock: even = stable generation, odd = writing. */
    uint32_t payload_len;  /* bytes of valid payload after this header. */
    uint32_t _pad;         /* must be zero; keeps payload 8-aligned. */
} HkSnapshotSlotHeader;
HK_STATIC_ASSERT(sizeof(HkSnapshotSlotHeader) == 16,
    "HkSnapshotSlotHeader size mismatch — update snapshot/ipc.rs in lockstep");

/* Ring header at offset 0 of the shm object. The slots begin at sizeof(this)
 * and are `slot_stride` bytes apart (stride includes the slot header). */
typedef struct HkSnapshotRingHeader {
    uint32_t magic;          /* == HK_SNAP_RING_MAGIC. */
    uint32_t schema_version; /* == HK_SNAPSHOT_SCHEMA_VERSION. */
    uint32_t slot_count;     /* number of ring slots (>= 2 so a reader never reads the slot being written). */
    uint32_t slot_stride;    /* bytes per slot: sizeof(HkSnapshotSlotHeader) + max payload. */
    uint64_t write_seq;      /* monotonic published-frame count; slot = (write_seq-1) % slot_count. */
    uint64_t _reserved;      /* must be zero. */
} HkSnapshotRingHeader;
HK_STATIC_ASSERT(sizeof(HkSnapshotRingHeader) == 32,
    "HkSnapshotRingHeader size mismatch — update snapshot/ipc.rs in lockstep");
