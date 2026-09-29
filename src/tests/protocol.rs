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

// ------------------------------------------------------------ file transfer

#[test]
fn file_messages_survive_a_roundtrip() {
    for msg in [
        Msg::FileStart {
            id: 3,
            name: "kitten.png".into(),
            mime: "image/png".into(),
            size: 4096,
        },
        Msg::FileChunk {
            id: 3,
            data: vec![0xAB; CHUNK_BYTES],
        },
        Msg::FileEnd { id: 3 },
        Msg::FileAbort {
            id: 3,
            reason: "changed my mind".into(),
        },
    ] {
        assert_eq!(Msg::decode(&msg.encode()).unwrap(), msg);
    }
}

#[test]
fn an_empty_chunk_is_still_valid() {
    let msg = Msg::FileChunk {
        id: 1,
        data: Vec::new(),
    };
    assert_eq!(Msg::decode(&msg.encode()).unwrap(), msg);
}

#[test]
fn chunk_bytes_are_preserved_exactly() {
    let data: Vec<u8> = (0..CHUNK_BYTES).map(|i| (i % 251) as u8).collect();
    let decoded = Msg::decode(
        &Msg::FileChunk {
            id: 9,
            data: data.clone(),
        }
        .encode(),
    )
    .unwrap();

    match decoded {
        Msg::FileChunk { data: got, .. } => assert_eq!(got, data),
        other => panic!("expected a chunk, got {other:?}"),
    }
}

#[test]
fn a_declared_size_over_the_limit_is_refused() {
    let mut frame = vec![TAG_FILE_START];
    frame.extend_from_slice(&1u32.to_be_bytes());
    frame.extend_from_slice(&(MAX_FILE_BYTES + 1).to_be_bytes());
    frame.extend_from_slice(&0u16.to_be_bytes());
    frame.extend_from_slice(&0u16.to_be_bytes());

    assert!(
        Msg::decode(&frame).is_err(),
        "a peer could declare an arbitrarily large allocation"
    );
}

#[test]
fn an_oversized_chunk_is_refused() {
    let mut frame = vec![TAG_FILE_CHUNK];
    frame.extend_from_slice(&1u32.to_be_bytes());
    frame.extend_from_slice(&((CHUNK_BYTES + 1) as u32).to_be_bytes());
    frame.extend_from_slice(&vec![0u8; CHUNK_BYTES + 1]);

    assert!(Msg::decode(&frame).is_err());
}

#[test]
fn a_chunk_shorter_than_its_header_claims_is_refused() {
    let mut frame = vec![TAG_FILE_CHUNK];
    frame.extend_from_slice(&1u32.to_be_bytes());
    frame.extend_from_slice(&512u32.to_be_bytes());
    frame.extend_from_slice(&[0u8; 8]);

    assert!(Msg::decode(&frame).is_err());
}

#[test]
fn an_overlong_filename_is_refused_rather_than_allocated() {
    let mut frame = vec![TAG_FILE_START];
    frame.extend_from_slice(&1u32.to_be_bytes());
    frame.extend_from_slice(&1024u64.to_be_bytes());
    frame.extend_from_slice(&((MAX_NAME + 1) as u16).to_be_bytes());
    frame.extend_from_slice(&vec![b'x'; MAX_NAME + 1]);

    assert!(Msg::decode(&frame).is_err());
}

#[test]
fn truncated_file_messages_error_rather_than_panic() {
    assert!(Msg::decode(&[TAG_FILE_START]).is_err());
    assert!(Msg::decode(&[TAG_FILE_START, 0, 0, 0, 1]).is_err());
    assert!(Msg::decode(&[TAG_FILE_CHUNK, 0, 0]).is_err());
    assert!(Msg::decode(&[TAG_FILE_END]).is_err());
    assert!(Msg::decode(&[TAG_FILE_ABORT, 0, 0, 0]).is_err());
}

#[test]
fn a_file_travels_sealed_and_in_order() {
    let key = [5u8; 32];
    let mut sender = Session::new(key, Role::Princess);
    let mut receiver = Session::new(key, Role::Daddy);

    let payload: Vec<u8> = (0..CHUNK_BYTES * 3 + 17).map(|i| (i % 253) as u8).collect();

    let mut frames = vec![sender.seal_msg(&Msg::FileStart {
        id: 1,
        name: "clip.mp4".into(),
        mime: "video/mp4".into(),
        size: payload.len() as u64,
    })];
    for chunk in payload.chunks(CHUNK_BYTES) {
        frames.push(sender.seal_msg(&Msg::FileChunk {
            id: 1,
            data: chunk.to_vec(),
        }));
    }
    frames.push(sender.seal_msg(&Msg::FileEnd { id: 1 }));

    // Nothing recognisable should be visible on the wire.
    assert!(
        !frames[0].windows(8).any(|w| w == b"clip.mp4"),
        "the filename leaked into a sealed frame"
    );

    let mut received = Vec::new();
    let mut ended = false;
    for frame in &frames {
        match receiver.open_msg(frame).unwrap() {
            Msg::FileChunk { data, .. } => received.extend_from_slice(&data),
            Msg::FileEnd { .. } => ended = true,
            Msg::FileStart { size, .. } => assert_eq!(size, payload.len() as u64),
            other => panic!("unexpected {other:?}"),
        }
    }

    assert!(ended);
    assert_eq!(received, payload, "the file did not survive the round trip");
}

#[test]
fn the_size_limit_exceeds_what_a_32_bit_usize_can_hold() {
    // This is why the file never passes through a Rust Vec: on wasm32 a cast
    // of this value to usize would silently truncate. If the limit is ever
    // lowered below 4 GiB, the streaming design is no longer forced and this
    // test should be revisited rather than deleted.
    assert!(
        MAX_FILE_BYTES > u32::MAX as u64,
        "the limit no longer exceeds u32::MAX"
    );
    assert_eq!(MAX_FILE_BYTES, 4608 * 1024 * 1024, "4.5 GiB");
}

#[test]
fn a_size_at_the_limit_round_trips_and_one_over_is_refused() {
    let at_limit = Msg::FileStart {
        id: 1,
        name: "huge.mp4".into(),
        mime: "video/mp4".into(),
        size: MAX_FILE_BYTES,
    };
    assert_eq!(Msg::decode(&at_limit.encode()).unwrap(), at_limit);

    let mut over = vec![TAG_FILE_START];
    over.extend_from_slice(&1u32.to_be_bytes());
    over.extend_from_slice(&(MAX_FILE_BYTES + 1).to_be_bytes());
    over.extend_from_slice(&0u16.to_be_bytes());
    over.extend_from_slice(&0u16.to_be_bytes());
    assert!(Msg::decode(&over).is_err());
}

#[test]
fn a_multi_gigabyte_size_survives_the_wire_intact() {
    // Four billion-plus must arrive unchanged; a u32 field or a usize cast
    // anywhere on this path would mangle it.
    let declared = 4_000_000_000u64;
    let decoded = Msg::decode(
        &Msg::FileStart {
            id: 7,
            name: "film.mkv".into(),
            mime: "video/x-matroska".into(),
            size: declared,
        }
        .encode(),
    )
    .unwrap();

    match decoded {
        Msg::FileStart { size, .. } => assert_eq!(size, declared),
        other => panic!("expected a file header, got {other:?}"),
    }
}
