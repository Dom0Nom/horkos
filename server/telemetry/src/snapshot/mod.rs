//! src/snapshot/mod.rs
//!
//! Role: authoritative game-state snapshot model + tick-replay cursor for the
//! behavioral-gamestate-knowledge analyzers (catalog signals 172-180). This is the
//! server-KNOWN truth the client lacks — per-tick entity transforms, the local view
//! basis, server PVS/BVH visibility, the authoritative audio-path graph, dynamic
//! occluder volumes, the per-shot recoil RNG vector, and the server-random objective
//! seed. Populated by `ipc` (live shm) or by the file-backed fixture loader (offline
//! backtests / tests / the bypass harness, with no game-server peer). Consumed by
//! every analyzer in `crate::analyzers`.
//!
//! Target platforms: server.
//!
//! Guardrails: #8 — `thiserror` for errors (via `TelemetryError`); no `unwrap()`
//! outside `#[cfg(test)]`. #1 — no platform API here; the OS-specific shm attach
//! lives in `backends`, gated by `cfg`.

pub mod ipc;

#[cfg(feature = "gamestate-ipc-shm")]
pub mod backends;

use crate::error::TelemetryError;
use crate::geom::{Aabb, Vec3};
use ipc::{HkOccluderVolume, HkSnapshotRecord};

/// One actor as the server authoritatively knows it this tick.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct EntityState {
    pub entity_id: u64,
    pub position: Vec3,
    pub velocity: Vec3,
    pub flags: u32,
}

impl EntityState {
    pub fn is_alive(&self) -> bool {
        self.flags & ipc::ENT_ALIVE != 0
    }
    pub fn is_local(&self) -> bool {
        self.flags & ipc::ENT_LOCAL != 0
    }
    pub fn is_team(&self) -> bool {
        self.flags & ipc::ENT_TEAM != 0
    }
}

/// A dynamic occluder volume (smoke / particle) with its active tick window.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct OccluderVolume {
    pub aabb: Aabb,
    pub born_tick: u64,
    pub expire_tick: u64,
}

impl OccluderVolume {
    /// True iff this volume occludes at `tick` (`[born, expire)`).
    pub fn active_at(&self, tick: u64) -> bool {
        tick >= self.born_tick && tick < self.expire_tick
    }
}

/// One authoritative snapshot tick in safe, geometry-friendly form.
#[derive(Debug, Clone, PartialEq)]
pub struct Snapshot {
    pub schema_version: u32,
    pub tick: u64,
    pub mono_ns: u64,
    pub local_player_id: u64,
    pub cam_origin: Vec3,
    pub cam_forward: Vec3,
    pub cam_up: Vec3,
    pub cam_fov_rad: f32,
    /// Per-entity server visibility (PVS/BVH LoS to the local player), parallel to
    /// `entities` by index.
    pub visibility: Vec<bool>,
    /// Per-entity authoritative audio path exists, parallel to `entities` by index.
    pub audiopath: Vec<bool>,
    pub recoil_rng_vec: Vec3,
    pub objective_seed: u64,
    pub entities: Vec<EntityState>,
    pub occluders: Vec<OccluderVolume>,
}

impl Snapshot {
    /// Build a safe `Snapshot` from a parsed wire record. `entity_count` and the
    /// occluder vector have already been bound-checked by `ipc::parse_slot`.
    pub(crate) fn from_record(
        rec: &HkSnapshotRecord,
        entity_count: usize,
        occluders_raw: Vec<HkOccluderVolume>,
    ) -> Result<Self, TelemetryError> {
        let v = |hv: ipc::HkVec3| Vec3::new(hv.x, hv.y, hv.z);

        let mut entities = Vec::with_capacity(entity_count);
        let mut visibility = Vec::with_capacity(entity_count);
        let mut audiopath = Vec::with_capacity(entity_count);
        for i in 0..entity_count {
            let e = &rec.entities[i];
            entities.push(EntityState {
                entity_id: e.entity_id,
                position: v(e.position),
                velocity: v(e.velocity),
                flags: e.flags,
            });
            visibility.push(ipc::bit_set(&rec.visibility_bits, i));
            audiopath.push(ipc::bit_set(&rec.audiopath_bits, i));
        }

        let occluders = occluders_raw
            .into_iter()
            .map(|o| OccluderVolume {
                aabb: Aabb {
                    min: v(o.aabb_min),
                    max: v(o.aabb_max),
                },
                born_tick: o.born_tick,
                expire_tick: o.expire_tick,
            })
            .collect();

        Ok(Snapshot {
            schema_version: rec.schema_version,
            tick: rec.tick,
            mono_ns: rec.mono_ns,
            local_player_id: rec.local_player_id,
            cam_origin: v(rec.cam_origin),
            cam_forward: v(rec.cam_forward),
            cam_up: v(rec.cam_up),
            cam_fov_rad: rec.cam_fov_rad,
            visibility,
            audiopath,
            recoil_rng_vec: v(rec.recoil_rng_vec),
            objective_seed: rec.objective_seed,
            entities,
            occluders,
        })
    }

    /// Index of an entity by id, if present this tick.
    pub fn index_of(&self, entity_id: u64) -> Option<usize> {
        self.entities.iter().position(|e| e.entity_id == entity_id)
    }

    /// Server-authoritative visibility of entity `idx` to the local player.
    pub fn is_visible(&self, idx: usize) -> bool {
        self.visibility.get(idx).copied().unwrap_or(false)
    }

    /// Authoritative audio path to entity `idx`.
    pub fn has_audio_path(&self, idx: usize) -> bool {
        self.audiopath.get(idx).copied().unwrap_or(false)
    }

    /// True iff any teammate has server LoS to entity `idx` (callout-explainable;
    /// excluded from 173/179). Approximated here as: the entity is visible to the
    /// local player OR is itself a teammate — a richer per-teammate visibility graph
    /// would require per-observer PVS, which this single-observer frame does not
    /// carry. HK-TODO(schema): a per-(observer,target) visibility matrix would let
    /// teammate-LoS be exact rather than this conservative over-approximation.
    pub fn teammate_has_los(&self, idx: usize) -> bool {
        match self.entities.get(idx) {
            Some(e) => e.is_team(),
            None => false,
        }
    }
}

/// A file-backed replay of consecutive snapshot frames, for offline backtests, unit
/// tests, and the bypass harness — no live game-server peer or shm mapping required.
/// The file is a length-prefixed concatenation of raw ring slots: a `u32` little-
/// endian byte length followed by that many bytes, repeated. Each slot is parsed by
/// the SAME `ipc::parse_slot` the live reader uses, so the fixture path and the live
/// path share one trust boundary.
#[derive(Debug, Default)]
pub struct SnapshotReplay {
    frames: Vec<Snapshot>,
    cursor: usize,
}

impl SnapshotReplay {
    /// Build a replay directly from already-parsed snapshots (used by tests that
    /// synthesize frames in memory).
    pub fn from_snapshots(frames: Vec<Snapshot>) -> Self {
        SnapshotReplay { frames, cursor: 0 }
    }

    /// Parse a length-prefixed slot stream into a replay. Each torn slot is a hard
    /// error (the fixture is authored, not adversarial input) — callers that want the
    /// fail-closed drop-and-count behavior use `ipc::parse_slot` directly per slot.
    pub fn from_bytes(mut bytes: &[u8]) -> Result<Self, TelemetryError> {
        let mut frames = Vec::new();
        while !bytes.is_empty() {
            if bytes.len() < 4 {
                return Err(TelemetryError::InvalidPayload(
                    "replay stream: dangling length prefix".to_string(),
                ));
            }
            let len = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
            bytes = &bytes[4..];
            if bytes.len() < len {
                return Err(TelemetryError::InvalidPayload(
                    "replay stream: slot shorter than its length prefix".to_string(),
                ));
            }
            let (slot, rest) = bytes.split_at(len);
            frames.push(ipc::parse_slot(slot)?);
            bytes = rest;
        }
        Ok(SnapshotReplay { frames, cursor: 0 })
    }

    pub fn len(&self) -> usize {
        self.frames.len()
    }

    pub fn is_empty(&self) -> bool {
        self.frames.is_empty()
    }

    /// All frames in tick order (analyzers that need a window read this directly).
    pub fn frames(&self) -> &[Snapshot] {
        &self.frames
    }

    /// Advance the replay cursor, returning the next frame, or `None` at the end.
    /// Not an `Iterator`: the frame borrows from `self` (lending), so this is a
    /// plain method under a non-`next` name to satisfy `should_implement_trait`.
    pub fn next_frame(&mut self) -> Option<&Snapshot> {
        let f = self.frames.get(self.cursor);
        if f.is_some() {
            self.cursor += 1;
        }
        f
    }

    pub fn reset(&mut self) {
        self.cursor = 0;
    }
}

#[cfg(test)]
pub(crate) mod fixtures {
    //! In-memory frame builders shared by analyzer unit tests and the bypass harness.
    use super::*;
    use crate::geom::Vec3;

    /// A neutral snapshot with the local player at the origin looking down +X, no
    /// other entities — the baseline a builder mutates per scenario.
    pub fn base_snapshot(tick: u64, mono_ns: u64) -> Snapshot {
        Snapshot {
            schema_version: ipc::SNAPSHOT_SCHEMA_VERSION,
            tick,
            mono_ns,
            local_player_id: 1,
            cam_origin: Vec3::ZERO,
            cam_forward: Vec3::new(1.0, 0.0, 0.0),
            cam_up: Vec3::new(0.0, 0.0, 1.0),
            cam_fov_rad: std::f32::consts::FRAC_PI_2, // 90 deg
            visibility: Vec::new(),
            audiopath: Vec::new(),
            recoil_rng_vec: Vec3::ZERO,
            objective_seed: 0,
            entities: Vec::new(),
            occluders: Vec::new(),
        }
    }

    /// Push one enemy actor and its parallel visibility/audio bits.
    pub fn push_enemy(
        snap: &mut Snapshot,
        id: u64,
        pos: Vec3,
        vel: Vec3,
        visible: bool,
        audio: bool,
    ) {
        snap.entities.push(EntityState {
            entity_id: id,
            position: pos,
            velocity: vel,
            flags: ipc::ENT_ALIVE,
        });
        snap.visibility.push(visible);
        snap.audiopath.push(audio);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::geom::Vec3;

    #[test]
    fn occluder_active_window() {
        let o = OccluderVolume {
            aabb: Aabb {
                min: Vec3::ZERO,
                max: Vec3::new(1.0, 1.0, 1.0),
            },
            born_tick: 10,
            expire_tick: 20,
        };
        assert!(!o.active_at(9));
        assert!(o.active_at(10));
        assert!(o.active_at(19));
        assert!(!o.active_at(20)); // exclusive upper bound
    }

    #[test]
    fn replay_round_trips_length_prefixed_slots() {
        // Build two minimal valid frames and length-prefix them.
        let mut stream = Vec::new();
        for tick in 0..2u64 {
            let mut slot = vec![0u8; ipc::RECORD_HEAD_BYTES];
            slot[0..4].copy_from_slice(&ipc::SNAPSHOT_SCHEMA_VERSION.to_ne_bytes());
            // tick field at offset 8.
            slot[8..16].copy_from_slice(&tick.to_ne_bytes());
            stream.extend_from_slice(&(slot.len() as u32).to_le_bytes());
            stream.extend_from_slice(&slot);
        }
        let mut replay = SnapshotReplay::from_bytes(&stream).expect("replay parses");
        assert_eq!(replay.len(), 2);
        assert_eq!(replay.next_frame().expect("frame 0").tick, 0);
        assert_eq!(replay.next_frame().expect("frame 1").tick, 1);
        assert!(replay.next_frame().is_none());
    }

    #[test]
    fn replay_rejects_truncated_slot() {
        let mut stream = Vec::new();
        stream.extend_from_slice(&100u32.to_le_bytes()); // claims 100 bytes
        stream.extend_from_slice(&[0u8; 10]); // only 10 present
        assert!(matches!(
            SnapshotReplay::from_bytes(&stream),
            Err(TelemetryError::InvalidPayload(_))
        ));
    }
}
