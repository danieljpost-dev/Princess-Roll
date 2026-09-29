//! Primitives shared by the native setup binary and the WASM app.
//!
//! Nothing in here touches storage. Keys live in memory for the life of a
//! session and are gone when the tab closes.

use aes_gcm::{
    aead::{Aead, Payload},
    Aes256Gcm, Key, KeyInit, Nonce,
};
use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};

/// Argon2id cost for unwrapping the pairing secret. Sized so a phone browser
/// spends roughly a second on it, while an offline attacker pays that same
/// second for every candidate code they try.
pub const ARGON2_M_KIB: u32 = 65536; // 64 MiB
pub const ARGON2_T_COST: u32 = 3;
pub const ARGON2_P_COST: u32 = 1;

/// Fill an array from the platform CSPRNG. On WASM this is `crypto.getRandomValues`.
pub fn random<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    getrandom::getrandom(&mut buf).expect("system CSPRNG unavailable");
    buf
}

/// Normalise a typed code so that stray whitespace never costs someone their
/// session. Case is preserved: the code is a secret, not a username.
pub fn normalize_code(code: &str) -> String {
    code.split_whitespace().collect::<Vec<_>>().join(" ")
}

pub fn argon2_key(code: &str, salt: &[u8], m_kib: u32, t: u32, p: u32) -> Result<[u8; 32], String> {
    let params =
        Params::new(m_kib, t, p, Some(32)).map_err(|e| format!("bad argon2 params: {e}"))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; 32];
    argon
        .hash_password_into(normalize_code(code).as_bytes(), salt, &mut out)
        .map_err(|e| format!("argon2 failed: {e}"))?;
    Ok(out)
}

pub fn hkdf32(ikm: &[u8], salt: &[u8], info: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut out = [0u8; 32];
    hk.expand(info, &mut out).expect("hkdf expand of 32 bytes");
    out
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

pub fn seal(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    cipher
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .expect("aes-gcm seal")
}

/// Returns `None` on any authentication failure. Callers treat that as "wrong
/// key" and must not distinguish it from "malformed input" in anything shown
/// to the user.
pub fn open(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], ciphertext: &[u8]) -> Option<Vec<u8>> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .ok()
}

/// Uniform integer in `1..=sides`, by rejection sampling. Modulo would bias the
/// low faces; on a die the whole point is that it does not.
pub fn uniform_die(seed: &[u8; 32], sides: u32) -> u32 {
    debug_assert!(sides > 0);
    let limit = u32::MAX - (u32::MAX % sides);
    let mut counter: u32 = 0;
    loop {
        let block = hkdf32(seed, b"princess-roll/die/v1", &counter.to_be_bytes());
        for word in 0..block.len() / 4 {
            let bytes: [u8; 4] = block[word * 4..word * 4 + 4].try_into().unwrap();
            let candidate = u32::from_be_bytes(bytes);
            if candidate < limit {
                return (candidate % sides) + 1;
            }
        }
        counter = counter.wrapping_add(1);
    }
}
