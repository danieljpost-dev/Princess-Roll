//! The invite and reply codes that the two of you paste to each other.
//!
//! A WebRTC offer carries your public IP address. These blobs are compressed,
//! then sealed under a key derived from the pairing secret, so whatever channel
//! you paste them through — SMS, Discord, a sticky note photographed badly —
//! sees only ciphertext. The two peers still learn each other's addresses once
//! connected; that is inherent to a direct connection and cannot be hidden
//! without routing through a relay.

use crate::crypto::{hkdf32, open, random, seal};
use crate::pairing::Role;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

const VERSION: u8 = 1;
const AAD: &[u8] = b"princess-roll/signal/v1";
/// SDP is a few kilobytes; this is generous while still bounding a hostile
/// decompression.
const MAX_INFLATED: usize = 256 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Invite,
    Reply,
}

impl Kind {
    fn tag(self) -> u8 {
        match self {
            Kind::Invite => 0,
            Kind::Reply => 1,
        }
    }

    fn from_tag(tag: u8) -> Result<Kind, String> {
        match tag {
            0 => Ok(Kind::Invite),
            1 => Ok(Kind::Reply),
            other => Err(format!("unknown signal kind {other}")),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Blob {
    pub kind: Kind,
    pub sender: Role,
    pub public_key: [u8; 32],
    pub sdp: String,
}

fn blob_key(pairing_secret: &[u8; 32]) -> [u8; 32] {
    hkdf32(pairing_secret, AAD, b"blob-key")
}

impl Blob {
    /// Seal into a paste-safe string. Compression happens before encryption —
    /// afterwards there would be nothing left to compress.
    pub fn encode(&self, pairing_secret: &[u8; 32]) -> String {
        let sdp = self.sdp.as_bytes();

        let mut plain = Vec::with_capacity(38 + sdp.len());
        plain.push(VERSION);
        plain.push(self.kind.tag());
        plain.push(match self.sender {
            Role::Daddy => 0,
            Role::Princess => 1,
        });
        plain.extend_from_slice(&self.public_key);
        plain.extend_from_slice(&(sdp.len() as u32).to_be_bytes());
        plain.extend_from_slice(sdp);

        let squeezed = miniz_oxide::deflate::compress_to_vec(&plain, 9);
        let nonce: [u8; 12] = random();
        let ct = seal(&blob_key(pairing_secret), &nonce, AAD, &squeezed);

        let mut wire = Vec::with_capacity(12 + ct.len());
        wire.extend_from_slice(&nonce);
        wire.extend_from_slice(&ct);
        URL_SAFE_NO_PAD.encode(wire)
    }

    /// Whitespace anywhere in the pasted text is ignored, because mail clients
    /// and chat apps wrap long strings and people paste what they see.
    pub fn decode(text: &str, pairing_secret: &[u8; 32]) -> Result<Blob, String> {
        let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();
        if compact.is_empty() {
            return Err("nothing pasted".into());
        }

        let wire = URL_SAFE_NO_PAD
            .decode(compact.as_bytes())
            .map_err(|_| "that does not look like a Princess-Roll code".to_string())?;
        if wire.len() < 13 {
            return Err("that code is too short to be valid".into());
        }

        let nonce: [u8; 12] = wire[0..12].try_into().unwrap();
        let squeezed = open(&blob_key(pairing_secret), &nonce, AAD, &wire[12..])
            .ok_or("this code was not made for your pair of secret codes")?;

        let plain = miniz_oxide::inflate::decompress_to_vec_with_limit(&squeezed, MAX_INFLATED)
            .map_err(|_| "that code is corrupt".to_string())?;

        if plain.len() < 39 {
            return Err("that code is truncated".into());
        }
        if plain[0] != VERSION {
            return Err(format!("unsupported code version {}", plain[0]));
        }

        let kind = Kind::from_tag(plain[1])?;
        let sender = match plain[2] {
            0 => Role::Daddy,
            1 => Role::Princess,
            other => return Err(format!("unknown sender role {other}")),
        };
        let public_key: [u8; 32] = plain[3..35].try_into().unwrap();
        let sdp_len = u32::from_be_bytes(plain[35..39].try_into().unwrap()) as usize;

        let body = &plain[39..];
        if body.len() != sdp_len {
            return Err("that code is truncated".into());
        }
        let sdp = String::from_utf8(body.to_vec())
            .map_err(|_| "that code contains invalid text".to_string())?;

        Ok(Blob {
            kind,
            sender,
            public_key,
            sdp,
        })
    }
}
