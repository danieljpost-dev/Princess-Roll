//! Tests for [`crate::pairing`].

use crate::pairing::{Pairing, Role, FILE_LEN};

/// Argon2 at production cost is far too slow to run dozens of times in a test
/// suite. `for_test` builds the identical structure at a trivial cost.
fn cheap(daddy: &str, princess: &str) -> (Pairing, [u8; 32]) {
    Pairing::for_test(daddy, princess)
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
