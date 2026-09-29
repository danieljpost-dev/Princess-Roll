//! Tests for [`crate::protocol`].

use crate::pairing::Role;
use crate::protocol::*;

fn pair() -> (Session, Session) {
    let key = [3u8; 32];
    (
        Session::new(key, Role::Daddy),
        Session::new(key, Role::Princess),
    )
}

#[test]
fn every_message_variant_survives_a_roundtrip() {
    for msg in [
        Msg::Chat("hello there".into()),
        Msg::Challenge {
            text: "recite it backwards".into(),
            threshold: 14,
        },
        Msg::ClearChallenge,
        Msg::Commit {
            round: 7,
            hash: [9u8; 32],
        },
        Msg::Reveal {
            round: 7,
            nonce: [4u8; 32],
        },
        Msg::Open {
            round: 7,
            nonce: [5u8; 32],
        },
    ] {
        assert_eq!(Msg::decode(&msg.encode()).unwrap(), msg);
    }
}

#[test]
fn frames_travel_in_both_directions() {
    let (mut daddy, mut princess) = pair();

    let frame = daddy.seal_msg(&Msg::Chat("from daddy".into()));
    assert_eq!(
        princess.open_msg(&frame).unwrap(),
        Msg::Chat("from daddy".into())
    );

    let frame = princess.seal_msg(&Msg::Chat("from princess".into()));
    assert_eq!(
        daddy.open_msg(&frame).unwrap(),
        Msg::Chat("from princess".into())
    );
}

#[test]
fn a_replayed_frame_is_refused() {
    let (mut daddy, mut princess) = pair();
    let frame = daddy.seal_msg(&Msg::Chat("once".into()));

    assert!(princess.open_msg(&frame).is_ok());
    assert!(
        princess.open_msg(&frame).is_err(),
        "the same frame was accepted twice"
    );
}

#[test]
fn a_sender_cannot_have_its_own_frame_reflected_back() {
    let (mut daddy, _) = pair();
    let frame = daddy.seal_msg(&Msg::Chat("mine".into()));
    let mut daddy_again = Session::new([3u8; 32], Role::Daddy);
    assert!(
        daddy_again.open_msg(&frame).is_err(),
        "a frame was readable in its own sending direction"
    );
}

#[test]
fn a_tampered_frame_fails_authentication() {
    let (mut daddy, mut princess) = pair();
    let mut frame = daddy.seal_msg(&Msg::Chat("intact".into()));
    let last = frame.len() - 1;
    frame[last] ^= 0x01;
    assert!(princess.open_msg(&frame).is_err());
}

#[test]
fn the_wrong_session_key_reads_nothing() {
    let mut daddy = Session::new([1u8; 32], Role::Daddy);
    let mut eavesdropper = Session::new([2u8; 32], Role::Princess);
    let frame = daddy.seal_msg(&Msg::Chat("secret".into()));
    assert!(eavesdropper.open_msg(&frame).is_err());
}

#[test]
fn plaintext_never_appears_in_a_frame() {
    let (mut daddy, _) = pair();
    let frame = daddy.seal_msg(&Msg::Chat("meet me at midnight".into()));
    assert!(
        !frame
            .windows(b"midnight".len())
            .any(|w| w == b"midnight"),
        "message text leaked into the sealed frame"
    );
}

#[test]
fn oversized_text_is_truncated_not_rejected() {
    let long = "x".repeat(MAX_TEXT * 2);
    let decoded = Msg::decode(&Msg::Chat(long).encode()).unwrap();
    match decoded {
        Msg::Chat(text) => assert_eq!(text.len(), MAX_TEXT),
        other => panic!("expected chat, got {other:?}"),
    }
}

#[test]
fn multibyte_text_truncates_on_a_character_boundary() {
    let long = "é".repeat(MAX_TEXT);
    let decoded = Msg::decode(&Msg::Chat(long).encode()).unwrap();
    match decoded {
        Msg::Chat(text) => assert!(text.len() <= MAX_TEXT && text.chars().all(|c| c == 'é')),
        other => panic!("expected chat, got {other:?}"),
    }
}

#[test]
fn malformed_input_is_an_error_not_a_panic() {
    assert!(Msg::decode(&[]).is_err());
    assert!(Msg::decode(&[99]).is_err());
    assert!(Msg::decode(&[TAG_CHAT]).is_err());
    assert!(Msg::decode(&[TAG_CHAT, 0, 50, b'a']).is_err());
    assert!(Msg::decode(&[TAG_COMMIT, 0, 0]).is_err());
    assert!(Msg::decode(&[TAG_CHAT, 0xff, 0xff]).is_err());
}

#[test]
fn both_sides_derive_the_same_session_key() {
    let shared = [11u8; 32];
    let pairing = [22u8; 32];
    let daddy_pub = [33u8; 32];
    let princess_pub = [44u8; 32];

    let a = derive_session_key(&shared, &pairing, &daddy_pub, &princess_pub);
    let b = derive_session_key(&shared, &pairing, &daddy_pub, &princess_pub);
    assert_eq!(a, b);
}

#[test]
fn the_session_key_depends_on_the_pairing_secret() {
    let shared = [11u8; 32];
    let with = derive_session_key(&shared, &[22u8; 32], &[33u8; 32], &[44u8; 32]);
    let without = derive_session_key(&shared, &[0u8; 32], &[33u8; 32], &[44u8; 32]);
    assert_ne!(
        with, without,
        "an attacker without the pairing secret would reach the same key"
    );
}

#[test]
fn swapping_the_public_keys_changes_the_session_key() {
    let shared = [11u8; 32];
    let pairing = [22u8; 32];
    let normal = derive_session_key(&shared, &pairing, &[33u8; 32], &[44u8; 32]);
    let swapped = derive_session_key(&shared, &pairing, &[44u8; 32], &[33u8; 32]);
    assert_ne!(normal, swapped);
}

#[test]
fn the_verification_phrase_is_stable_and_key_dependent() {
    let phrase = verification_phrase(&[7u8; 32]);
    assert_eq!(phrase, verification_phrase(&[7u8; 32]));
    assert_ne!(phrase, verification_phrase(&[8u8; 32]));

    let syllables: Vec<&str> = phrase.split('-').collect();
    assert_eq!(syllables.len(), 4);
    assert!(syllables.iter().all(|s| s.len() == 3));
}
