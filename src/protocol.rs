//! Everything that travels over the open data channel.
//!
//! Each direction owns a nonce space keyed by sender, and counters must
//! strictly increase, so a frame can be neither replayed nor reflected back at
//! its author. The channel underneath is already DTLS-encrypted by WebRTC;
//! this layer means the payload stays sealed even if that were not true.

use crate::crypto::{hkdf32, open, seal};
use crate::pairing::Role;

const NONCE_PREFIX: [u8; 3] = [b'P', b'R', 1];

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Msg {
    Chat(String),
    /// Daddy sets the challenge text and the number Princess must meet.
    Challenge { text: String, threshold: u8 },
    ClearChallenge,
    /// Daddy publishes SHA256(nonce) before Princess can roll.
    Commit { round: u32, hash: [u8; 32] },
    /// Princess answers with her own nonce, which starts the roll.
    Reveal { round: u32, nonce: [u8; 32] },
    /// Daddy opens his commitment; both sides now derive the same result.
    Open { round: u32, nonce: [u8; 32] },

    /// Announces a file. Chunks follow, then `FileEnd`.
    FileStart {
        id: u32,
        name: String,
        mime: String,
        size: u64,
    },
    /// One slice of the file in flight. The data channel is ordered and
    /// reliable, so chunks carry no index of their own.
    FileChunk { id: u32, data: Vec<u8> },
    FileEnd { id: u32 },
    /// Sent when the sender gives up, so the receiver can drop what it holds
    /// instead of waiting for bytes that will never arrive.
    FileAbort { id: u32, reason: String },
}

pub(crate) const TAG_CHAT: u8 = 1;
pub(crate) const TAG_CHALLENGE: u8 = 2;
pub(crate) const TAG_CLEAR: u8 = 3;
pub(crate) const TAG_COMMIT: u8 = 4;
pub(crate) const TAG_REVEAL: u8 = 5;
pub(crate) const TAG_OPEN: u8 = 6;
pub(crate) const TAG_FILE_START: u8 = 7;
pub(crate) const TAG_FILE_CHUNK: u8 = 8;
pub(crate) const TAG_FILE_END: u8 = 9;
pub(crate) const TAG_FILE_ABORT: u8 = 10;

/// Bounded so a peer cannot force an unbounded allocation.
pub const MAX_TEXT: usize = 2000;

/// Filenames and MIME types are short. Anything longer is a mistake or an
/// attempt to make the receiver allocate.
pub const MAX_NAME: usize = 260;

/// The largest file that may be sent: 4.5 GiB.
///
/// This is deliberately larger than wasm32 can address. Neither side ever
/// holds the file in linear memory — the sender reads it in slices and the
/// receiver hands each chunk straight to the browser as a blob part — so the
/// 4 GiB wasm ceiling does not apply. It is a `u64` and must never be cast to
/// `usize`: on wasm32 that truncates above 4,294,967,295 and this limit is
/// above it.
pub const MAX_FILE_BYTES: u64 = 4608 * 1024 * 1024;

/// Payload carried by one chunk, comfortably under every browser's
/// data-channel message limit once AEAD and framing overhead are added.
pub const CHUNK_BYTES: usize = 32 * 1024;

impl Msg {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            Msg::Chat(text) => {
                out.push(TAG_CHAT);
                put_str(&mut out, text);
            }
            Msg::Challenge { text, threshold } => {
                out.push(TAG_CHALLENGE);
                out.push(*threshold);
                put_str(&mut out, text);
            }
            Msg::ClearChallenge => out.push(TAG_CLEAR),
            Msg::Commit { round, hash } => {
                out.push(TAG_COMMIT);
                out.extend_from_slice(&round.to_be_bytes());
                out.extend_from_slice(hash);
            }
            Msg::Reveal { round, nonce } => {
                out.push(TAG_REVEAL);
                out.extend_from_slice(&round.to_be_bytes());
                out.extend_from_slice(nonce);
            }
            Msg::Open { round, nonce } => {
                out.push(TAG_OPEN);
                out.extend_from_slice(&round.to_be_bytes());
                out.extend_from_slice(nonce);
            }
            Msg::FileStart {
                id,
                name,
                mime,
                size,
            } => {
                out.push(TAG_FILE_START);
                out.extend_from_slice(&id.to_be_bytes());
                out.extend_from_slice(&size.to_be_bytes());
                put_str_max(&mut out, name, MAX_NAME);
                put_str_max(&mut out, mime, MAX_NAME);
            }
            Msg::FileChunk { id, data } => {
                out.push(TAG_FILE_CHUNK);
                out.extend_from_slice(&id.to_be_bytes());
                out.extend_from_slice(&(data.len() as u32).to_be_bytes());
                out.extend_from_slice(data);
            }
            Msg::FileEnd { id } => {
                out.push(TAG_FILE_END);
                out.extend_from_slice(&id.to_be_bytes());
            }
            Msg::FileAbort { id, reason } => {
                out.push(TAG_FILE_ABORT);
                out.extend_from_slice(&id.to_be_bytes());
                put_str_max(&mut out, reason, MAX_TEXT);
            }
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Msg, String> {
        let (&tag, rest) = bytes.split_first().ok_or("empty message")?;
        match tag {
            TAG_CHAT => Ok(Msg::Chat(take_str(rest)?.0)),
            TAG_CHALLENGE => {
                let (&threshold, rest) = rest.split_first().ok_or("challenge missing threshold")?;
                Ok(Msg::Challenge {
                    text: take_str(rest)?.0,
                    threshold,
                })
            }
            TAG_CLEAR => Ok(Msg::ClearChallenge),
            TAG_COMMIT => {
                let (round, hash) = take_round_and_32(rest)?;
                Ok(Msg::Commit { round, hash })
            }
            TAG_REVEAL => {
                let (round, nonce) = take_round_and_32(rest)?;
                Ok(Msg::Reveal { round, nonce })
            }
            TAG_OPEN => {
                let (round, nonce) = take_round_and_32(rest)?;
                Ok(Msg::Open { round, nonce })
            }
            TAG_FILE_START => {
                if rest.len() < 12 {
                    return Err("truncated file header".into());
                }
                let id = u32::from_be_bytes(rest[0..4].try_into().unwrap());
                let size = u64::from_be_bytes(rest[4..12].try_into().unwrap());
                if size > MAX_FILE_BYTES {
                    return Err("that file is larger than the agreed maximum".into());
                }
                let (name, rest) = take_str_max(&rest[12..], MAX_NAME)?;
                let (mime, _) = take_str_max(rest, MAX_NAME)?;
                Ok(Msg::FileStart {
                    id,
                    name,
                    mime,
                    size,
                })
            }
            TAG_FILE_CHUNK => {
                if rest.len() < 8 {
                    return Err("truncated chunk header".into());
                }
                let id = u32::from_be_bytes(rest[0..4].try_into().unwrap());
                let len = u32::from_be_bytes(rest[4..8].try_into().unwrap()) as usize;
                if len > CHUNK_BYTES {
                    return Err("chunk exceeds the agreed size".into());
                }
                let body = &rest[8..];
                if body.len() < len {
                    return Err("truncated chunk body".into());
                }
                Ok(Msg::FileChunk {
                    id,
                    data: body[..len].to_vec(),
                })
            }
            TAG_FILE_END => {
                if rest.len() < 4 {
                    return Err("truncated file end".into());
                }
                Ok(Msg::FileEnd {
                    id: u32::from_be_bytes(rest[0..4].try_into().unwrap()),
                })
            }
            TAG_FILE_ABORT => {
                if rest.len() < 4 {
                    return Err("truncated file abort".into());
                }
                let id = u32::from_be_bytes(rest[0..4].try_into().unwrap());
                let (reason, _) = take_str_max(&rest[4..], MAX_TEXT)?;
                Ok(Msg::FileAbort { id, reason })
            }
            other => Err(format!("unknown message tag {other}")),
        }
    }
}

fn put_str(out: &mut Vec<u8>, text: &str) {
    put_str_max(out, text, MAX_TEXT);
}

fn put_str_max(out: &mut Vec<u8>, text: &str, max: usize) {
    let truncated = clamp_chars(text, max);
    out.extend_from_slice(&(truncated.len() as u16).to_be_bytes());
    out.extend_from_slice(truncated.as_bytes());
}

/// Truncate on a character boundary so the result is always valid UTF-8.
fn clamp_chars(text: &str, max_bytes: usize) -> &str {
    if text.len() <= max_bytes {
        return text;
    }
    let mut end = max_bytes;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

fn take_str(bytes: &[u8]) -> Result<(String, &[u8]), String> {
    take_str_max(bytes, MAX_TEXT)
}

fn take_str_max(bytes: &[u8], max: usize) -> Result<(String, &[u8]), String> {
    if bytes.len() < 2 {
        return Err("truncated string header".into());
    }
    let len = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
    if len > max {
        return Err("string exceeds maximum length".into());
    }
    let rest = &bytes[2..];
    if rest.len() < len {
        return Err("truncated string body".into());
    }
    let text = std::str::from_utf8(&rest[..len])
        .map_err(|_| "string is not valid UTF-8".to_string())?
        .to_string();
    Ok((text, &rest[len..]))
}

fn take_round_and_32(bytes: &[u8]) -> Result<(u32, [u8; 32]), String> {
    if bytes.len() < 36 {
        return Err("truncated round payload".into());
    }
    let round = u32::from_be_bytes(bytes[0..4].try_into().unwrap());
    let value: [u8; 32] = bytes[4..36].try_into().unwrap();
    Ok((round, value))
}

/// Combine the X25519 shared secret with the pairing secret. Folding the
/// pairing secret in as the HKDF salt is what stops a stranger who intercepts
/// both invite codes from completing a handshake: without it, no session key.
/// Both public keys go into `info` in a fixed role order so the two sides
/// always agree and neither can be reflected.
pub fn derive_session_key(
    shared: &[u8; 32],
    pairing_secret: &[u8; 32],
    daddy_public: &[u8; 32],
    princess_public: &[u8; 32],
) -> [u8; 32] {
    let mut info = Vec::with_capacity(24 + 64);
    info.extend_from_slice(b"princess-roll/session/v1");
    info.extend_from_slice(daddy_public);
    info.extend_from_slice(princess_public);
    hkdf32(shared, pairing_secret, &info)
}

/// A short pronounceable fingerprint of the session key. Both screens show it;
/// if they match, nobody is sitting in the middle.
pub fn verification_phrase(session_key: &[u8; 32]) -> String {
    const CONSONANTS: &[u8] = b"bdfgklmnprstvz";
    const VOWELS: &[u8] = b"aeiou";

    let material = hkdf32(session_key, b"princess-roll/sas/v1", b"phrase");
    (0..4)
        .map(|i| {
            let slot = u16::from_be_bytes([material[i * 2], material[i * 2 + 1]]) as usize;
            let index = slot % (CONSONANTS.len() * VOWELS.len() * CONSONANTS.len());
            let head = CONSONANTS[index % CONSONANTS.len()] as char;
            let mid = VOWELS[(index / CONSONANTS.len()) % VOWELS.len()] as char;
            let tail = CONSONANTS[index / (CONSONANTS.len() * VOWELS.len())] as char;
            format!("{head}{mid}{tail}")
        })
        .collect::<Vec<_>>()
        .join("-")
}

/// Sealed framing over the data channel. Holds the only copy of the session
/// key; dropping it ends the session's ability to read anything.
pub struct Session {
    key: [u8; 32],
    my_direction: u8,
    send_counter: u64,
    highest_seen: Option<u64>,
}

impl Session {
    pub fn new(key: [u8; 32], role: Role) -> Self {
        Session {
            key,
            my_direction: role.direction(),
            send_counter: 0,
            highest_seen: None,
        }
    }

    fn nonce(direction: u8, counter: u64) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[0..3].copy_from_slice(&NONCE_PREFIX);
        nonce[3] = direction;
        nonce[4..12].copy_from_slice(&counter.to_be_bytes());
        nonce
    }

    pub fn seal_msg(&mut self, msg: &Msg) -> Vec<u8> {
        let counter = self.send_counter;
        self.send_counter += 1;

        let nonce = Self::nonce(self.my_direction, counter);
        let ct = seal(&self.key, &nonce, &[self.my_direction], &msg.encode());

        let mut frame = Vec::with_capacity(8 + ct.len());
        frame.extend_from_slice(&counter.to_be_bytes());
        frame.extend_from_slice(&ct);
        frame
    }

    pub fn open_msg(&mut self, frame: &[u8]) -> Result<Msg, String> {
        if frame.len() < 9 {
            return Err("frame too short".into());
        }
        let counter = u64::from_be_bytes(frame[0..8].try_into().unwrap());
        if self.highest_seen.is_some_and(|seen| counter <= seen) {
            return Err("replayed or out-of-order frame rejected".into());
        }

        let peer_direction = 1 - self.my_direction;
        let nonce = Self::nonce(peer_direction, counter);
        let plain = open(&self.key, &nonce, &[peer_direction], &frame[8..])
            .ok_or("frame failed authentication")?;

        let msg = Msg::decode(&plain)?;
        self.highest_seen = Some(counter);
        Ok(msg)
    }
}
