//! The die: its geometry, its fairness, and how it lands where it was told to.
//!
//! The result is agreed between both clients *before* anything animates, so the
//! tumble is a choreography problem rather than a physics one. The path is
//! random and derived from a shared seed — both screens see the identical
//! throw — but the endpoint is fixed, so the die always seats the agreed face
//! toward the camera. No retries, no snapping, no relabelled faces.

use crate::crypto::{hkdf32, sha256, uniform_die};
use subtle::ConstantTimeEq;

pub const SIDES: u32 = 20;

// ---------------------------------------------------------------- vector math

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Vec3 {
    pub x: f32,
    pub y: f32,
    pub z: f32,
}

impl Vec3 {
    pub const fn new(x: f32, y: f32, z: f32) -> Self {
        Vec3 { x, y, z }
    }

    pub fn dot(self, o: Vec3) -> f32 {
        self.x * o.x + self.y * o.y + self.z * o.z
    }

    pub fn cross(self, o: Vec3) -> Vec3 {
        Vec3::new(
            self.y * o.z - self.z * o.y,
            self.z * o.x - self.x * o.z,
            self.x * o.y - self.y * o.x,
        )
    }

    pub fn length(self) -> f32 {
        self.dot(self).sqrt()
    }

    pub fn normalized(self) -> Vec3 {
        let len = self.length();
        if 0.0 == len {
            self
        } else {
            self * (1.0 / len)
        }
    }
}

impl std::ops::Add for Vec3 {
    type Output = Vec3;
    fn add(self, o: Vec3) -> Vec3 {
        Vec3::new(self.x + o.x, self.y + o.y, self.z + o.z)
    }
}

impl std::ops::Sub for Vec3 {
    type Output = Vec3;
    fn sub(self, o: Vec3) -> Vec3 {
        Vec3::new(self.x - o.x, self.y - o.y, self.z - o.z)
    }
}

impl std::ops::Mul<f32> for Vec3 {
    type Output = Vec3;
    fn mul(self, k: f32) -> Vec3 {
        Vec3::new(self.x * k, self.y * k, self.z * k)
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Quat {
    pub w: f32,
    pub x: f32,
    pub y: f32,
    pub z: f32,
}

impl Quat {
    pub const IDENTITY: Quat = Quat {
        w: 1.0,
        x: 0.0,
        y: 0.0,
        z: 0.0,
    };

    pub fn from_axis_angle(axis: Vec3, angle: f32) -> Quat {
        let axis = axis.normalized();
        let half = angle * 0.5;
        let s = half.sin();
        Quat {
            w: half.cos(),
            x: axis.x * s,
            y: axis.y * s,
            z: axis.z * s,
        }
    }

    pub fn normalized(self) -> Quat {
        let n = (self.w * self.w + self.x * self.x + self.y * self.y + self.z * self.z).sqrt();
        if 0.0 == n {
            Quat::IDENTITY
        } else {
            Quat {
                w: self.w / n,
                x: self.x / n,
                y: self.y / n,
                z: self.z / n,
            }
        }
    }

    pub fn rotate(self, v: Vec3) -> Vec3 {
        let u = Vec3::new(self.x, self.y, self.z);
        let t = u.cross(v) * 2.0;
        v + t * self.w + u.cross(t)
    }

    /// For unit quaternions this is the cosine of half the angle between the
    /// two orientations, so `|dot|` near 1 means "almost the same rotation".
    pub fn dot(self, o: Quat) -> f32 {
        self.w * o.w + self.x * o.x + self.y * o.y + self.z * o.z
    }

    /// Shortest-arc interpolation. `t` beyond 1 extrapolates, which is what
    /// gives the die its overshoot as it settles.
    pub fn slerp(self, target: Quat, t: f32) -> Quat {
        let mut end = target;
        let mut cos = self.dot(target);
        if cos < 0.0 {
            end = Quat {
                w: -end.w,
                x: -end.x,
                y: -end.y,
                z: -end.z,
            };
            cos = -cos;
        }

        // Nearly parallel: lerp and renormalise, since sin(theta) underflows.
        if cos > 0.9995 {
            return Quat {
                w: self.w + (end.w - self.w) * t,
                x: self.x + (end.x - self.x) * t,
                y: self.y + (end.y - self.y) * t,
                z: self.z + (end.z - self.z) * t,
            }
            .normalized();
        }

        let theta = cos.clamp(-1.0, 1.0).acos();
        let sin_theta = theta.sin();
        let a = ((1.0 - t) * theta).sin() / sin_theta;
        let b = (t * theta).sin() / sin_theta;
        Quat {
            w: self.w * a + end.w * b,
            x: self.x * a + end.x * b,
            y: self.y * a + end.y * b,
            z: self.z * a + end.z * b,
        }
        .normalized()
    }

    /// The rotation carrying `from` onto `to`, both assumed unit length.
    pub fn rotation_between(from: Vec3, to: Vec3) -> Quat {
        let d = from.dot(to);
        if d > 0.999999 {
            return Quat::IDENTITY;
        }
        if d < -0.999999 {
            // Antipodal: any perpendicular axis gives a valid half turn.
            let mut axis = Vec3::new(1.0, 0.0, 0.0).cross(from);
            if axis.length() < 1e-6 {
                axis = Vec3::new(0.0, 1.0, 0.0).cross(from);
            }
            return Quat::from_axis_angle(axis, std::f32::consts::PI);
        }
        let axis = from.cross(to);
        let s = ((1.0 + d) * 2.0).sqrt();
        Quat {
            w: s * 0.5,
            x: axis.x / s,
            y: axis.y / s,
            z: axis.z / s,
        }
        .normalized()
    }
}

impl std::ops::Mul for Quat {
    type Output = Quat;
    /// Composition: `a * b` applies `b` first, then `a`.
    fn mul(self, o: Quat) -> Quat {
        Quat {
            w: self.w * o.w - self.x * o.x - self.y * o.y - self.z * o.z,
            x: self.w * o.x + self.x * o.w + self.y * o.z - self.z * o.y,
            y: self.w * o.y - self.x * o.z + self.y * o.w + self.z * o.x,
            z: self.w * o.z + self.x * o.y - self.y * o.x + self.z * o.w,
        }
    }
}

// ----------------------------------------------------------------- icosahedron

/// Where a landed face ends up pointing. The camera sits on +Z, so this aims
/// the winning face straight at the viewer.
pub const VIEWER: Vec3 = Vec3::new(0.0, 0.0, 1.0);

pub struct Geometry {
    vertices: [Vec3; 12],
    faces: [[usize; 3]; 20],
    numbers: [u32; 20],
}

impl Default for Geometry {
    fn default() -> Self {
        Self::new()
    }
}

impl Geometry {
    pub fn new() -> Self {
        let phi = (1.0 + 5.0f32.sqrt()) * 0.5;
        let v = |x: f32, y: f32, z: f32| Vec3::new(x, y, z).normalized();
        let vertices = [
            v(-1.0, phi, 0.0),
            v(1.0, phi, 0.0),
            v(-1.0, -phi, 0.0),
            v(1.0, -phi, 0.0),
            v(0.0, -1.0, phi),
            v(0.0, 1.0, phi),
            v(0.0, -1.0, -phi),
            v(0.0, 1.0, -phi),
            v(phi, 0.0, -1.0),
            v(phi, 0.0, 1.0),
            v(-phi, 0.0, -1.0),
            v(-phi, 0.0, 1.0),
        ];

        let faces = [
            [0, 11, 5],
            [0, 5, 1],
            [0, 1, 7],
            [0, 7, 10],
            [0, 10, 11],
            [1, 5, 9],
            [5, 11, 4],
            [11, 10, 2],
            [10, 7, 6],
            [7, 1, 8],
            [3, 9, 4],
            [3, 4, 2],
            [3, 2, 6],
            [3, 6, 8],
            [3, 8, 9],
            [4, 9, 5],
            [2, 4, 11],
            [6, 2, 10],
            [8, 6, 7],
            [9, 8, 1],
        ];

        let mut geom = Geometry {
            vertices,
            faces,
            numbers: [0; 20],
        };
        geom.assign_numbers();
        geom
    }

    /// Number the faces the way a real d20 is numbered: opposite faces sum to
    /// 21. Found by pairing each face with its antipode rather than hard-coding
    /// a table, so it stays correct if the face list is ever reordered.
    fn assign_numbers(&mut self) {
        let mut next = 1;
        for i in 0..20 {
            if 0 != self.numbers[i] {
                continue;
            }
            let normal = self.face_normal(i);
            let opposite = (0..20)
                .find(|&j| j != i && self.face_normal(j).dot(normal) < -0.99)
                .expect("every icosahedron face has an antipode");
            self.numbers[i] = next;
            self.numbers[opposite] = 21 - next;
            next += 1;
        }
    }

    pub fn faces(&self) -> &[[usize; 3]; 20] {
        &self.faces
    }

    pub fn vertex(&self, i: usize) -> Vec3 {
        self.vertices[i]
    }

    pub fn number(&self, face: usize) -> u32 {
        self.numbers[face]
    }

    pub fn face_centroid(&self, face: usize) -> Vec3 {
        let [a, b, c] = self.faces[face];
        (self.vertices[a] + self.vertices[b] + self.vertices[c]) * (1.0 / 3.0)
    }

    pub fn face_normal(&self, face: usize) -> Vec3 {
        self.face_centroid(face).normalized()
    }

    /// An in-plane reference direction for the face, used both to orient the
    /// printed number and to build its texture coordinates. Taking the first
    /// vertex means the digit's "up" is the same in model space and on screen.
    pub fn face_up(&self, face: usize) -> Vec3 {
        let centroid = self.face_centroid(face);
        (self.vertices[self.faces[face][0]] - centroid).normalized()
    }

    /// Where a face's corner sits inside its texture cell, as (u, v) in 0..1
    /// with v increasing upward.
    ///
    /// Derived from the face's own tangent frame rather than from the order of
    /// the vertices in the face table. Assuming a winding order is what
    /// mirrored the printed numbers: on any face wound the other way, left and
    /// right swapped. This cannot.
    pub fn face_corner_uv(&self, face: usize, corner: usize) -> (f32, f32) {
        /// How much of the cell the face's circumradius spans.
        const FIT: f32 = 0.45;

        let centroid = self.face_centroid(face);
        let up = self.face_up(face);
        // With the face aimed at the viewer and `up` pointing up the screen,
        // this is screen-right.
        let right = up.cross(self.face_normal(face));

        let radius = (self.vertices[self.faces[face][0]] - centroid).length();
        let offset = self.vertices[self.faces[face][corner]] - centroid;

        (
            0.5 + offset.dot(right) / radius * FIT,
            0.5 + offset.dot(up) / radius * FIT,
        )
    }

    pub fn face_index_for(&self, number: u32) -> usize {
        self.numbers
            .iter()
            .position(|&n| n == number)
            .expect("every value 1..=20 is printed on exactly one face")
    }

    /// The orientation that seats `number` squarely toward the viewer, with the
    /// printed digit the right way up.
    pub fn orientation_for(&self, number: u32) -> Quat {
        let face = self.face_index_for(number);
        let aim = Quat::rotation_between(self.face_normal(face), VIEWER);

        // Aiming the normal leaves the digit spun by an arbitrary angle about
        // the view axis. Undo that so the number reads upright.
        let up = aim.rotate(self.face_up(face));
        let correction = std::f32::consts::FRAC_PI_2 - up.y.atan2(up.x);

        (Quat::from_axis_angle(VIEWER, correction) * aim).normalized()
    }
}

// ------------------------------------------------------------------- fair roll

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Roll {
    pub value: u32,
    pub animation_seed: [u8; 32],
}

impl Roll {
    pub fn succeeds_against(&self, threshold: u8) -> bool {
        self.value >= threshold as u32
    }
}

pub fn commit_to(nonce: &[u8; 32]) -> [u8; 32] {
    sha256(nonce)
}

/// Constant-time so a peer cannot learn anything from how long a check took.
pub fn commit_matches(commitment: &[u8; 32], nonce: &[u8; 32]) -> bool {
    commit_to(nonce).ct_eq(commitment).into()
}

/// Both nonces contribute, so neither side alone decides the outcome. Daddy is
/// bound by a commitment published before Princess reveals hers; she cannot
/// see his choice, and he cannot change his after seeing hers.
pub fn derive_roll(daddy_nonce: &[u8; 32], princess_nonce: &[u8; 32]) -> Roll {
    let mut combined = [0u8; 64];
    combined[..32].copy_from_slice(daddy_nonce);
    combined[32..].copy_from_slice(princess_nonce);

    let seed = hkdf32(&combined, b"princess-roll/roll/v1", b"combine");
    Roll {
        value: uniform_die(&seed, SIDES),
        animation_seed: hkdf32(&seed, b"princess-roll/roll/v1", b"animation"),
    }
}

// ----------------------------------------------------------------- choreography

pub const TUMBLE_SECONDS: f32 = 2.6;

fn ease_out_quart(t: f32) -> f32 {
    1.0 - (1.0 - t).powi(4)
}

/// Overshoots slightly before settling, which is what makes the landing read as
/// a die coming to rest rather than a model snapping into place.
fn ease_out_back(t: f32) -> f32 {
    const C1: f32 = 1.70158;
    const C3: f32 = C1 + 1.0;
    let p = t - 1.0;
    1.0 + C3 * p * p * p + C1 * p * p
}

/// A deterministic throw. Built from the shared animation seed, so both screens
/// render the same tumble, and ending exactly on the agreed face.
pub struct Tumble {
    start: Quat,
    target: Quat,
    axis: Vec3,
    total_spin: f32,
    arc_height: f32,
}

impl Tumble {
    /// `blend` stays at zero for the first half so the die spins freely, then
    /// pulls it onto the target. At `t == 1` it is exactly 1, which is why the
    /// landing is exact rather than approximate.
    const SETTLE_FROM: f32 = 0.5;

    pub fn new(geometry: &Geometry, value: u32, seed: &[u8; 32], start: Quat) -> Tumble {
        let unit = |offset: usize| {
            let bytes: [u8; 4] = seed[offset..offset + 4].try_into().unwrap();
            u32::from_be_bytes(bytes) as f32 / u32::MAX as f32
        };

        // A tumbling axis that is never degenerate, biased away from pure spin
        // about the view axis so the throw always shows some face travel.
        let axis = Vec3::new(
            unit(0) * 2.0 - 1.0,
            unit(4) * 2.0 - 1.0,
            (unit(8) * 2.0 - 1.0) * 0.35,
        );
        let axis = if axis.length() < 0.2 {
            Vec3::new(0.6, 0.8, 0.1)
        } else {
            axis.normalized()
        };

        let turns = 3.0 + unit(12) * 2.5;
        Tumble {
            start,
            target: geometry.orientation_for(value),
            axis,
            total_spin: turns * std::f32::consts::TAU,
            arc_height: 0.55 + unit(16) * 0.25,
        }
    }

    fn blend(t: f32) -> f32 {
        if t <= Self::SETTLE_FROM {
            0.0
        } else {
            ease_out_back((t - Self::SETTLE_FROM) / (1.0 - Self::SETTLE_FROM))
        }
    }

    pub fn orientation_at(&self, t: f32) -> Quat {
        let t = t.clamp(0.0, 1.0);
        let spinning =
            Quat::from_axis_angle(self.axis, self.total_spin * ease_out_quart(t)) * self.start;
        spinning.slerp(self.target, Self::blend(t))
    }

    /// Vertical offset: one high arc, then two decaying bounces.
    pub fn height_at(&self, t: f32) -> f32 {
        let t = t.clamp(0.0, 1.0);
        let hop = |from: f32, to: f32, scale: f32| {
            if t < from || t >= to {
                0.0
            } else {
                let u = (t - from) / (to - from);
                (u * std::f32::consts::PI).sin() * self.arc_height * scale
            }
        };
        hop(0.0, 0.55, 1.0) + hop(0.55, 0.80, 0.24) + hop(0.80, 0.95, 0.07)
    }

    pub fn target(&self) -> Quat {
        self.target
    }
}
