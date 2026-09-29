//! Tests for [`crate::dice`].

use crate::crypto::hkdf32;
use crate::dice::*;

fn approx(a: f32, b: f32, tol: f32) -> bool {
    (a - b).abs() < tol
}

#[test]
fn the_die_has_twenty_faces_numbered_one_to_twenty() {
    let geom = Geometry::new();
    let mut seen: Vec<u32> = (0..20).map(|f| geom.number(f)).collect();
    seen.sort_unstable();
    assert_eq!(seen, (1..=20).collect::<Vec<_>>());
}

#[test]
fn opposite_faces_sum_to_twenty_one() {
    let geom = Geometry::new();
    for face in 0..20 {
        let normal = geom.face_normal(face);
        let opposite = (0..20)
            .find(|&j| j != face && geom.face_normal(j).dot(normal) < -0.99)
            .expect("antipode exists");
        assert_eq!(
            geom.number(face) + geom.number(opposite),
            21,
            "faces {face} and {opposite} do not sum to 21"
        );
    }
}

#[test]
fn every_face_is_a_unit_distance_triangle() {
    let geom = Geometry::new();
    for face in 0..20 {
        let [a, b, c] = geom.faces()[face];
        let edges = [
            (geom.vertex(a) - geom.vertex(b)).length(),
            (geom.vertex(b) - geom.vertex(c)).length(),
            (geom.vertex(c) - geom.vertex(a)).length(),
        ];
        for pair in edges.windows(2) {
            assert!(
                approx(pair[0], pair[1], 1e-4),
                "face {face} is not equilateral: {edges:?}"
            );
        }
    }
}

#[test]
fn orientation_aims_the_requested_face_at_the_viewer() {
    let geom = Geometry::new();
    for value in 1..=20 {
        let q = geom.orientation_for(value);
        let landed = q.rotate(geom.face_normal(geom.face_index_for(value)));
        assert!(
            landed.dot(VIEWER) > 0.9999,
            "face {value} landed pointing {landed:?}"
        );
    }
}

#[test]
fn the_printed_number_lands_upright() {
    let geom = Geometry::new();
    for value in 1..=20 {
        let q = geom.orientation_for(value);
        let up = q.rotate(geom.face_up(geom.face_index_for(value)));
        assert!(
            up.y > 0.99,
            "face {value} landed with its digit rotated: up = {up:?}"
        );
    }
}

#[test]
fn faces_are_wound_counter_clockwise_when_seen_from_outside() {
    let geom = Geometry::new();
    for face in 0..20 {
        let [a, b, c] = geom.faces()[face];
        let edge1 = geom.vertex(b) - geom.vertex(a);
        let edge2 = geom.vertex(c) - geom.vertex(a);
        assert!(
            edge1.cross(edge2).dot(geom.face_normal(face)) > 0.0,
            "face {face} is wound inward; back-face culling would hide it"
        );
    }
}

/// The regression test for mirrored numbers: a corner to the right in the
/// texture must be to the right on screen once the face is aimed at the
/// viewer. Hard-coding corner positions by assumed winding broke exactly
/// this.
#[test]
fn texture_coordinates_share_the_screens_handedness() {
    let geom = Geometry::new();
    for value in 1..=20 {
        let face = geom.face_index_for(value);
        let orientation = geom.orientation_for(value);
        let centroid = geom.face_centroid(face);

        for corner in 0..3 {
            let (u, v) = geom.face_corner_uv(face, corner);
            let offset = geom.vertex(geom.faces()[face][corner]) - centroid;
            let on_screen = orientation.rotate(offset);

            if (u - 0.5).abs() > 0.02 {
                assert_eq!(
                    (u - 0.5).is_sign_positive(),
                    on_screen.x.is_sign_positive(),
                    "face {value} corner {corner}: texture u={u} but screen x={}",
                    on_screen.x
                );
            }
            if (v - 0.5).abs() > 0.02 {
                assert_eq!(
                    (v - 0.5).is_sign_positive(),
                    on_screen.y.is_sign_positive(),
                    "face {value} corner {corner}: texture v={v} but screen y={}",
                    on_screen.y
                );
            }
        }
    }
}

#[test]
fn every_texture_coordinate_stays_inside_its_cell() {
    let geom = Geometry::new();
    for face in 0..20 {
        for corner in 0..3 {
            let (u, v) = geom.face_corner_uv(face, corner);
            assert!((0.0..=1.0).contains(&u), "face {face} corner {corner}: u={u}");
            assert!((0.0..=1.0).contains(&v), "face {face} corner {corner}: v={v}");
        }
    }
}

#[test]
fn each_cell_has_one_corner_on_top_and_a_level_base() {
    let geom = Geometry::new();
    for face in 0..20 {
        let mut heights: Vec<f32> = (0..3).map(|c| geom.face_corner_uv(face, c).1).collect();
        heights.sort_by(|a, b| a.partial_cmp(b).expect("no NaN in texture coordinates"));

        assert!(heights[2] > 0.9, "face {face} has no apex: {heights:?}");
        assert!(
            (heights[0] - heights[1]).abs() < 1e-4 && heights[1] < 0.35,
            "face {face} does not have a level base: {heights:?}"
        );
    }
}

#[test]
fn a_tumble_ends_exactly_on_the_agreed_face() {
    let geom = Geometry::new();
    for value in 1..=20 {
        for variant in 0..5u8 {
            let seed = hkdf32(&[value as u8, variant], b"test", b"seed");
            let tumble = Tumble::new(&geom, value, &seed, Quat::IDENTITY);

            let landed = tumble
                .orientation_at(1.0)
                .rotate(geom.face_normal(geom.face_index_for(value)));
            assert!(
                landed.dot(VIEWER) > 0.9995,
                "value {value} variant {variant} missed: {landed:?}"
            );
        }
    }
}

#[test]
fn a_tumble_actually_moves_before_it_settles() {
    let geom = Geometry::new();
    let seed = hkdf32(b"motion", b"test", b"seed");
    let tumble = Tumble::new(&geom, 7, &seed, Quat::IDENTITY);

    let early = tumble.orientation_at(0.1);
    assert!(
        early.dot(Quat::IDENTITY).abs() < 0.999,
        "the die barely rotated at the start of the throw"
    );
    assert!(tumble.height_at(0.25) > 0.1, "the die never left the ground");
    assert!(approx(tumble.height_at(1.0), 0.0, 1e-5), "the die never landed");
    assert!(approx(tumble.height_at(0.0), 0.0, 1e-5));
}

#[test]
fn the_orientation_path_has_no_sudden_jumps() {
    let geom = Geometry::new();
    let seed = hkdf32(b"smooth", b"test", b"seed");
    let tumble = Tumble::new(&geom, 13, &seed, Quat::IDENTITY);

    let steps = 600;
    let mut previous = tumble.orientation_at(0.0);
    for step in 1..=steps {
        let current = tumble.orientation_at(step as f32 / steps as f32);
        // Angular step between consecutive frames, via the quaternion dot.
        let cos = previous.dot(current).abs().clamp(0.0, 1.0);
        let angle = 2.0 * cos.acos();
        assert!(
            angle < 0.6,
            "jump of {angle} rad at step {step} of the tumble"
        );
        previous = current;
    }
}

#[test]
fn the_same_seed_produces_the_same_throw_on_both_screens() {
    let geom = Geometry::new();
    let seed = hkdf32(b"shared", b"test", b"seed");
    let a = Tumble::new(&geom, 9, &seed, Quat::IDENTITY);
    let b = Tumble::new(&geom, 9, &seed, Quat::IDENTITY);

    for step in 0..=20 {
        let t = step as f32 / 20.0;
        assert_eq!(a.orientation_at(t), b.orientation_at(t));
        assert_eq!(a.height_at(t), b.height_at(t));
    }
}

#[test]
fn different_seeds_take_different_paths_to_the_same_face() {
    let geom = Geometry::new();
    let a = Tumble::new(&geom, 9, &hkdf32(b"one", b"test", b"s"), Quat::IDENTITY);
    let b = Tumble::new(&geom, 9, &hkdf32(b"two", b"test", b"s"), Quat::IDENTITY);

    assert_ne!(a.orientation_at(0.3), b.orientation_at(0.3));
    assert!(
        a.target().dot(b.target()).abs() > 0.9999,
        "both throws should still land on the same face"
    );
}

#[test]
fn both_peers_derive_the_same_roll() {
    let daddy = [1u8; 32];
    let princess = [2u8; 32];
    assert_eq!(derive_roll(&daddy, &princess), derive_roll(&daddy, &princess));
}

#[test]
fn swapping_the_nonces_changes_the_roll() {
    let daddy = [1u8; 32];
    let princess = [2u8; 32];
    assert_ne!(
        derive_roll(&daddy, &princess).animation_seed,
        derive_roll(&princess, &daddy).animation_seed
    );
}

#[test]
fn either_side_changing_its_nonce_changes_the_result() {
    let base = derive_roll(&[1u8; 32], &[2u8; 32]);
    assert_ne!(base.animation_seed, derive_roll(&[9u8; 32], &[2u8; 32]).animation_seed);
    assert_ne!(base.animation_seed, derive_roll(&[1u8; 32], &[9u8; 32]).animation_seed);
}

#[test]
fn rolls_stay_in_range_and_cover_every_face() {
    let mut seen = [false; 21];
    for i in 0..5000u32 {
        let daddy = hkdf32(&i.to_be_bytes(), b"d", b"n");
        let princess = hkdf32(&i.to_be_bytes(), b"p", b"n");
        let roll = derive_roll(&daddy, &princess);
        assert!((1..=20).contains(&roll.value));
        seen[roll.value as usize] = true;
    }
    assert!(seen[1..=20].iter().all(|&s| s));
}

#[test]
fn a_commitment_verifies_only_against_its_own_nonce() {
    let nonce = [7u8; 32];
    assert!(commit_matches(&commit_to(&nonce), &nonce));
    assert!(!commit_matches(&commit_to(&nonce), &[8u8; 32]));
    assert!(!commit_matches(&[0u8; 32], &nonce));
}

#[test]
fn success_is_meeting_the_threshold_not_beating_it() {
    let at = Roll {
        value: 14,
        animation_seed: [0; 32],
    };
    assert!(at.succeeds_against(14), "rolling exactly the threshold must succeed");
    assert!(at.succeeds_against(13));
    assert!(!at.succeeds_against(15));
}

#[test]
fn slerp_reaches_both_ends_exactly() {
    let a = Quat::from_axis_angle(Vec3::new(0.0, 1.0, 0.0), 0.3);
    let b = Quat::from_axis_angle(Vec3::new(1.0, 0.0, 0.0), 2.1);
    assert!(a.slerp(b, 0.0).dot(a).abs() > 0.9999);
    assert!(a.slerp(b, 1.0).dot(b).abs() > 0.9999);
}

#[test]
fn rotation_between_handles_parallel_and_antipodal_vectors() {
    let up = Vec3::new(0.0, 1.0, 0.0);
    assert!(Quat::rotation_between(up, up).rotate(up).dot(up) > 0.9999);

    let down = Vec3::new(0.0, -1.0, 0.0);
    assert!(Quat::rotation_between(up, down).rotate(up).dot(down) > 0.9999);
}
