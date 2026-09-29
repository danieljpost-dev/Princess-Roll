//! Tests for [`crate::pairing`].

use crate::crypto::{argon2_key, random, seal};
use crate::pairing::{aad_for, Pairing, Role, FILE_LEN};

/// The same construction as `Pairing::create`, at trivial Argon2 cost.
///
/// The real parameters are deliberately expensive — that is the point in
/// production, and unusable in a suite that builds dozens of these.
fn cheap(daddy_code: &str, princess_code: &str) -> (Pairing, [u8; 32]) {
    const CHEAP_M_KIB: u32 = 8;
    const CHEAP_T_COST: u32 = 1;
    const CHEAP_P_COST: u32 = 1;

    let salt: [u8; 16] = random();
    let secret: [u8; 32] = random();

    let mut wraps = Vec::with_capacity(2);
    for (role, code) in [(Role::Daddy, daddy_code), (Role::Princess, princess_code)] {
        let key = argon2_key(code, &salt, CHEAP_M_KIB, CHEAP_T_COST, CHEAP_P_COST)
            .expect("cheap argon2 parameters are valid");
        let nonce: [u8; 12] = random();
        wraps.push((nonce, seal(&key, &nonce, &aad_for(role), &secret)));
    }

    let princess_wrap = wraps.pop().unwrap();
    let daddy_wrap = wraps.pop().unwrap();

    (
        Pairing {
            m_kib: CHEAP_M_KIB,
            t_cost: CHEAP_T_COST,
            p_cost: CHEAP_P_COST,
            salt,
            wraps: [daddy_wrap, princess_wrap],
        },
        secret,
    )
}

#[test]
fn each_code_unlocks_its_own_role_and_the_same_secret() {
    let (pairing, secret) = cheap("code-alpha", "code-bravo");

    let (role_a, secret_a) = pairing.unlock("code-alpha").unwrap();
    assert_eq!(role_a, Role::Daddy);
    assert_eq!(secret_a, secret);

    let (role_b, secret_b) = pairing.unlock("code-bravo").unwrap();
    assert_eq!(role_b, Role::Princess);
    assert_eq!(secret_b, secret, "both codes must reach the same secret");
}

#[test]
fn a_wrong_code_unlocks_nothing() {
    let (pairing, _) = cheap("code-alpha", "code-bravo");
    assert!(pairing.unlock("code-charlie").is_none());
    assert!(pairing.unlock("").is_none());
}

#[test]
fn whitespace_around_a_code_is_forgiven() {
    let (pairing, _) = cheap("six word code goes here now", "code-bravo");
    let (role, _) = pairing.unlock("  six  word code\tgoes here now  ").unwrap();
    assert_eq!(role, Role::Daddy);
}

#[test]
fn encode_decode_roundtrip_preserves_behaviour() {
    let (pairing, secret) = cheap("code-alpha", "code-bravo");
    let bytes = pairing.encode();
    assert_eq!(bytes.len(), FILE_LEN);

    let restored = Pairing::decode(&bytes).unwrap();
    let (role, recovered) = restored.unlock("code-bravo").unwrap();
    assert_eq!(role, Role::Princess);
    assert_eq!(recovered, secret);
}

#[test]
fn the_file_never_contains_the_secret_in_the_clear() {
    let (pairing, secret) = cheap("code-alpha", "code-bravo");
    let bytes = pairing.encode();
    assert!(
        !bytes.windows(32).any(|w| w == secret),
        "pairing secret leaked into the shipped file"
    );
}

#[test]
fn decode_rejects_corrupt_input() {
    let (pairing, _) = cheap("code-alpha", "code-bravo");
    let good = pairing.encode();

    assert!(Pairing::decode(&good[..good.len() - 1]).is_err());

    let mut bad_magic = good.clone();
    bad_magic[0] = b'X';
    assert!(Pairing::decode(&bad_magic).is_err());

    let mut bad_version = good.clone();
    bad_version[4] = 99;
    assert!(Pairing::decode(&bad_version).is_err());
}

#[test]
fn a_tampered_wrap_fails_to_open() {
    let (pairing, _) = cheap("code-alpha", "code-bravo");
    let mut bytes = pairing.encode();
    let last = bytes.len() - 1;
    bytes[last] ^= 0xff;
    assert!(Pairing::decode(&bytes).unwrap().unlock("code-bravo").is_none());
}

#[test]
fn roles_are_opposites_with_distinct_directions() {
    assert_eq!(Role::Daddy.other(), Role::Princess);
    assert_eq!(Role::Princess.other(), Role::Daddy);
    assert_ne!(Role::Daddy.direction(), Role::Princess.direction());
}
