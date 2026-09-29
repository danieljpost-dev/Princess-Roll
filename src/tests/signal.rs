//! Tests for [`crate::signal`].

use crate::pairing::Role;
use crate::signal::{Blob, Kind};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

fn sample(kind: Kind, sender: Role) -> Blob {
    Blob {
        kind,
        sender,
        public_key: [5u8; 32],
        sdp: "v=0\r\no=- 4611731400430051336 2 IN IP4 203.0.113.7\r\n".repeat(8),
    }
}

#[test]
fn a_blob_survives_the_round_trip() {
    let secret = [1u8; 32];
    let blob = sample(Kind::Invite, Role::Daddy);
    let decoded = Blob::decode(&blob.encode(&secret), &secret).unwrap();
    assert_eq!(decoded, blob);
}

#[test]
fn both_kinds_and_both_roles_round_trip() {
    let secret = [1u8; 32];
    for kind in [Kind::Invite, Kind::Reply] {
        for sender in [Role::Daddy, Role::Princess] {
            let blob = sample(kind, sender);
            let decoded = Blob::decode(&blob.encode(&secret), &secret).unwrap();
            assert_eq!(decoded.kind, kind);
            assert_eq!(decoded.sender, sender);
        }
    }
}

#[test]
fn the_wrong_pairing_secret_reveals_nothing() {
    let blob = sample(Kind::Invite, Role::Daddy);
    let encoded = blob.encode(&[1u8; 32]);
    assert!(Blob::decode(&encoded, &[2u8; 32]).is_err());
}

#[test]
fn the_ip_address_never_appears_in_the_encoded_code() {
    let secret = [1u8; 32];
    let encoded = sample(Kind::Invite, Role::Daddy).encode(&secret);
    assert!(
        !encoded.contains("203.0.113.7"),
        "an IP address leaked into the pasted code"
    );
    assert!(!encoded.contains("v=0"), "raw SDP leaked into the pasted code");
}

#[test]
fn wrapped_and_padded_paste_still_decodes() {
    let secret = [1u8; 32];
    let encoded = sample(Kind::Reply, Role::Princess).encode(&secret);

    let wrapped = encoded
        .as_bytes()
        .chunks(40)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect::<Vec<_>>()
        .join("\n");
    let messy = format!("  \n{wrapped}\n  ");

    assert_eq!(Blob::decode(&messy, &secret).unwrap().sdp, sample(Kind::Reply, Role::Princess).sdp);
}

#[test]
fn two_encodings_of_the_same_blob_differ() {
    let secret = [1u8; 32];
    let blob = sample(Kind::Invite, Role::Daddy);
    assert_ne!(
        blob.encode(&secret),
        blob.encode(&secret),
        "a repeated nonce would be a serious flaw"
    );
}

#[test]
fn garbage_input_is_rejected_without_panicking() {
    let secret = [1u8; 32];
    for junk in ["", "   ", "not base64 at all!!!", "AAAA", &"A".repeat(500)] {
        assert!(Blob::decode(junk, &secret).is_err(), "accepted {junk:?}");
    }
}

#[test]
fn a_flipped_bit_is_caught() {
    let secret = [1u8; 32];
    let encoded = sample(Kind::Invite, Role::Daddy).encode(&secret);
    let mut bytes = URL_SAFE_NO_PAD.decode(encoded.as_bytes()).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0x80;
    assert!(Blob::decode(&URL_SAFE_NO_PAD.encode(&bytes), &secret).is_err());
}

#[test]
fn compression_actually_helps() {
    let secret = [1u8; 32];
    let blob = sample(Kind::Invite, Role::Daddy);
    assert!(
        blob.encode(&secret).len() < blob.sdp.len(),
        "the pasted code should be smaller than the raw SDP"
    );
}
