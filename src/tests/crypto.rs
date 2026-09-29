//! Tests for [`crate::crypto`].

use crate::crypto::*;

#[test]
fn seal_open_roundtrip() {
    let key = [7u8; 32];
    let nonce = [9u8; 12];
    let ct = seal(&key, &nonce, b"aad", b"hello");
    assert_eq!(open(&key, &nonce, b"aad", &ct).unwrap(), b"hello");
}

#[test]
fn open_rejects_wrong_key_nonce_and_aad() {
    let key = [7u8; 32];
    let nonce = [9u8; 12];
    let ct = seal(&key, &nonce, b"aad", b"hello");
    assert!(open(&[8u8; 32], &nonce, b"aad", &ct).is_none());
    assert!(open(&key, &[0u8; 12], b"aad", &ct).is_none());
    assert!(open(&key, &nonce, b"other", &ct).is_none());
}

#[test]
fn normalize_code_collapses_whitespace() {
    assert_eq!(normalize_code("  one   two\tthree \n"), "one two three");
    assert_eq!(normalize_code("Case Kept"), "Case Kept");
}

#[test]
fn die_stays_in_range_and_covers_every_face() {
    let mut seen = [false; 21];
    for i in 0..4000u32 {
        let seed = hkdf32(&i.to_be_bytes(), b"test", b"seed");
        let roll = uniform_die(&seed, 20);
        assert!((1..=20).contains(&roll), "roll {roll} out of range");
        seen[roll as usize] = true;
    }
    assert!(seen[1..=20].iter().all(|&s| s), "some faces never appeared");
}

#[test]
fn die_is_deterministic_for_a_given_seed() {
    let seed = [42u8; 32];
    assert_eq!(uniform_die(&seed, 20), uniform_die(&seed, 20));
}
