//! Role: Pure geometry / visibility math for the behavioral-gamestate analyzers
//! (catalog signals 172-180). Ray-vs-AABB, view-frustum containment, angular error
//! between an aim vector and a target direction, and view-basis reconstruction from
//! the snapshot camera fields. No I/O, no state, no platform API — every function is
//! a total math function over its inputs and fully unit-testable on the host.
//!
//! Target platforms: server.
//!
//! Guardrails: #8 — no `unwrap()`/`expect()` outside `#[cfg(test)]`; functions are
//! total (a degenerate input such as a zero-length vector returns a defined,
//! non-panicking result rather than NaN-propagating a fabricated signal).

/// A 3-vector mirroring the snapshot `HkVec3`. Plain `f32` math; `Copy`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Vec3 {
    pub x: f32,
    pub y: f32,
    pub z: f32,
}

impl Vec3 {
    pub const ZERO: Vec3 = Vec3 {
        x: 0.0,
        y: 0.0,
        z: 0.0,
    };

    pub fn new(x: f32, y: f32, z: f32) -> Self {
        Vec3 { x, y, z }
    }

    pub fn dot(self, o: Vec3) -> f32 {
        self.x * o.x + self.y * o.y + self.z * o.z
    }

    pub fn len(self) -> f32 {
        self.dot(self).max(0.0).sqrt()
    }

    /// Unit vector. A zero-length input returns `ZERO` (not NaN) — callers treat a
    /// zero direction as "no usable direction" rather than a fabricated aim.
    pub fn normalized(self) -> Vec3 {
        let l = self.len();
        if l <= f32::EPSILON {
            Vec3::ZERO
        } else {
            Vec3::new(self.x / l, self.y / l, self.z / l)
        }
    }
}

impl std::ops::Sub for Vec3 {
    type Output = Vec3;

    fn sub(self, o: Vec3) -> Vec3 {
        Vec3::new(self.x - o.x, self.y - o.y, self.z - o.z)
    }
}

impl std::ops::Add for Vec3 {
    type Output = Vec3;

    fn add(self, o: Vec3) -> Vec3 {
        Vec3::new(self.x + o.x, self.y + o.y, self.z + o.z)
    }
}

/// An axis-aligned bounding box (min/max corners), mirroring `HkOccluderVolume`'s box.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Aabb {
    pub min: Vec3,
    pub max: Vec3,
}

/// Angular error (radians) between an aim direction and the direction from the view
/// origin to a target point. Returns `None` when either direction is degenerate
/// (zero length) — the caller must not treat an undefined angle as a sub-degree lock.
/// Result is in `[0, PI]`.
pub fn angular_error(aim_dir: Vec3, view_origin: Vec3, target: Vec3) -> Option<f32> {
    let a = aim_dir.normalized();
    let t = (target - view_origin).normalized();
    if a == Vec3::ZERO || t == Vec3::ZERO {
        return None;
    }
    // Clamp guards against floating error pushing the dot just outside [-1, 1].
    let cos = a.dot(t).clamp(-1.0, 1.0);
    Some(cos.acos())
}

/// Reconstruct a normalized view basis (forward, up) from the raw snapshot camera
/// fields. Re-normalizes `forward`; produces an orthonormal `up` via Gram-Schmidt so
/// a slightly non-orthogonal engine basis still yields a valid frame. Returns `None`
/// if `forward` is degenerate.
pub fn view_basis(cam_forward: Vec3, cam_up: Vec3) -> Option<(Vec3, Vec3)> {
    let fwd = cam_forward.normalized();
    if fwd == Vec3::ZERO {
        return None;
    }
    // up' = up - (up.fwd) fwd, then normalize. Falls back to a canonical world-up
    // projection if the supplied up is parallel to forward.
    let proj = fwd.dot(cam_up);
    let mut up = Vec3::new(
        cam_up.x - proj * fwd.x,
        cam_up.y - proj * fwd.y,
        cam_up.z - proj * fwd.z,
    )
    .normalized();
    if up == Vec3::ZERO {
        // Supplied up was parallel to forward; pick world-Z then world-Y as fallback.
        let world_z = Vec3::new(0.0, 0.0, 1.0);
        let p = fwd.dot(world_z);
        up = Vec3::new(-p * fwd.x, -p * fwd.y, 1.0 - p * fwd.z).normalized();
        if up == Vec3::ZERO {
            let world_y = Vec3::new(0.0, 1.0, 0.0);
            let p2 = fwd.dot(world_y);
            up = Vec3::new(-p2 * fwd.x, 1.0 - p2 * fwd.y, -p2 * fwd.z).normalized();
        }
    }
    Some((fwd, up))
}

/// True iff `target` lies within the view frustum's half-angle cone of `cam_forward`
/// from `cam_origin`. `fov_rad` is the FULL horizontal field of view; the half-angle
/// is `fov_rad / 2`. A target exactly on the boundary counts as contained (`<=`).
/// A degenerate forward or a target at the origin returns `false` (cannot be "seen").
pub fn frustum_contains(cam_origin: Vec3, cam_forward: Vec3, fov_rad: f32, target: Vec3) -> bool {
    if fov_rad <= 0.0 {
        return false;
    }
    match angular_error(cam_forward, cam_origin, target) {
        Some(ang) => ang <= (fov_rad * 0.5),
        None => false,
    }
}

/// Slab-method ray-vs-AABB intersection. Returns `true` if the ray from `origin`
/// along `dir` (need not be unit) hits `aabb` at any t >= 0. A zero direction is a
/// point test: true iff the origin is inside the box. Branch-free per-axis with the
/// standard inf-handling for axis-parallel rays.
pub fn ray_aabb(origin: Vec3, dir: Vec3, aabb: Aabb) -> bool {
    if dir == Vec3::ZERO {
        return point_in_aabb(origin, aabb);
    }
    let mut tmin = f32::NEG_INFINITY;
    let mut tmax = f32::INFINITY;

    let axes = [
        (origin.x, dir.x, aabb.min.x, aabb.max.x),
        (origin.y, dir.y, aabb.min.y, aabb.max.y),
        (origin.z, dir.z, aabb.min.z, aabb.max.z),
    ];
    for (o, d, lo, hi) in axes {
        if d.abs() <= f32::EPSILON {
            // Ray parallel to this slab: miss if the origin is outside the slab.
            if o < lo || o > hi {
                return false;
            }
        } else {
            let inv = 1.0 / d;
            let mut t0 = (lo - o) * inv;
            let mut t1 = (hi - o) * inv;
            if t0 > t1 {
                core::mem::swap(&mut t0, &mut t1);
            }
            tmin = tmin.max(t0);
            tmax = tmax.min(t1);
            if tmin > tmax {
                return false;
            }
        }
    }
    // Hit only counts forward along the ray (t >= 0).
    tmax >= 0.0
}

/// True iff `p` is inside (or on the surface of) `aabb`.
pub fn point_in_aabb(p: Vec3, aabb: Aabb) -> bool {
    p.x >= aabb.min.x
        && p.x <= aabb.max.x
        && p.y >= aabb.min.y
        && p.y <= aabb.max.y
        && p.z >= aabb.min.z
        && p.z <= aabb.max.z
}

/// Apply a yaw (rotation about the basis up axis) and pitch (rotation about the
/// basis right axis) to a view forward, returning the new unit forward. Used to turn
/// the client-reported integrated `aim_delta_*` (yaw/pitch radians) into a 3-D aim
/// direction in the snapshot's authoritative frame, so an aim can be compared against
/// an authoritative world position (signals 172/177). `forward`/`up` are taken from
/// `view_basis`; a degenerate basis yields the re-normalized forward unchanged.
pub fn aim_from_yaw_pitch(forward: Vec3, up: Vec3, yaw: f32, pitch: f32) -> Vec3 {
    let fwd = forward.normalized();
    let upn = up.normalized();
    if fwd == Vec3::ZERO || upn == Vec3::ZERO {
        return fwd;
    }
    // right = up x forward (left-handed-agnostic; we only need a consistent frame).
    let right = cross(upn, fwd).normalized();
    if right == Vec3::ZERO {
        return fwd;
    }
    // Yaw about up, then pitch about the (rotated) right axis. Compose by rotating
    // the forward vector: f' = cos(yaw)*fwd + sin(yaw)*right (yaw plane), then pitch
    // tilts toward up. This is a small-angle-safe exact rotation in the basis plane.
    let (sy, cy) = yaw.sin_cos();
    let yawed = Vec3::new(
        cy * fwd.x + sy * right.x,
        cy * fwd.y + sy * right.y,
        cy * fwd.z + sy * right.z,
    )
    .normalized();
    let pitch_axis = cross(upn, yawed).normalized(); // right axis after yaw
    let _ = pitch_axis; // pitch rotates yawed toward up:
    let (sp, cp) = pitch.sin_cos();
    Vec3::new(
        cp * yawed.x + sp * upn.x,
        cp * yawed.y + sp * upn.y,
        cp * yawed.z + sp * upn.z,
    )
    .normalized()
}

/// Right-handed cross product.
pub fn cross(a: Vec3, b: Vec3) -> Vec3 {
    Vec3::new(
        a.y * b.z - a.z * b.y,
        a.z * b.x - a.x * b.z,
        a.x * b.y - a.y * b.x,
    )
}

/// True iff the segment from `a` to `b` passes through `aabb` (used to ask "does the
/// line of sight from the view origin to a target pierce a smoke volume" — signal
/// 175). Equivalent to a ray test bounded to t in [0, 1].
pub fn segment_intersects_aabb(a: Vec3, b: Vec3, aabb: Aabb) -> bool {
    let dir = b - a;
    if dir == Vec3::ZERO {
        return point_in_aabb(a, aabb);
    }
    let mut tmin = 0.0_f32;
    let mut tmax = 1.0_f32;
    let axes = [
        (a.x, dir.x, aabb.min.x, aabb.max.x),
        (a.y, dir.y, aabb.min.y, aabb.max.y),
        (a.z, dir.z, aabb.min.z, aabb.max.z),
    ];
    for (o, d, lo, hi) in axes {
        if d.abs() <= f32::EPSILON {
            if o < lo || o > hi {
                return false;
            }
        } else {
            let inv = 1.0 / d;
            let mut t0 = (lo - o) * inv;
            let mut t1 = (hi - o) * inv;
            if t0 > t1 {
                core::mem::swap(&mut t0, &mut t1);
            }
            tmin = tmin.max(t0);
            tmax = tmax.min(t1);
            if tmin > tmax {
                return false;
            }
        }
    }
    true
}
