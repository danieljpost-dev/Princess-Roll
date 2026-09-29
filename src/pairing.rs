//! The `pairing.bin` blob that ships with the page.
//!
//! It holds one random pairing secret, wrapped twice — once under each secret
//! code. Entering a valid code unwraps the same secret and, as a side effect,
//! reveals which role you are: the AEAD tag only verifies against the wrap
//! whose role matches. Nothing in the file is plaintext, and the file says
//! nothing about who either person is.

use crate::crypto::{argon2_key, open, random, seal, ARGON2_M_KIB, ARGON2_P_COST, ARGON2_T_COST};

const MAGIC: &[u8; 4] = b"PRL1";
const VERSION: u8 = 1;
const AAD_PREFIX: &[u8] = b"princess-roll/pairing/v1";
const WRAP_LEN: usize = 48; // 32-byte secret + 16-byte GCM tag
pub const FILE_LEN: usize = 4 + 1 + 12 + 16 + 2 * (12 + WRAP_LEN);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Daddy,
    Princess,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Daddy => "Daddy",
            Role::Princess => "Princess",
        }
    }

    fn tag(self) -> u8 {
        match self {
            Role::Daddy => 0,
            Role::Princess => 1,
        }
    }

    /// Message counters are namespaced by sender so the two directions can
    /// never collide on a nonce.
    pub fn direction(self) -> u8 {
        self.tag()
    }

    pub fn other(self) -> Role {
        match self {
            Role::Daddy => Role::Princess,
            Role::Princess => Role::Daddy,
        }
    }
}

pub(crate) fn aad_for(role: Role) -> Vec<u8> {
    let mut aad = AAD_PREFIX.to_vec();
    aad.push(role.tag());
    aad
}

pub struct Pairing {
    // `pub(crate)` so the test suite can build one directly. A `pub`
    // struct in a `pub` module still hides these from outside the crate,
    // so the published API is unchanged.
    pub(crate) m_kib: u32,
    pub(crate) t_cost: u32,
    pub(crate) p_cost: u32,
    pub(crate) salt: [u8; 16],
    pub(crate) wraps: [([u8; 12], Vec<u8>); 2],
}

impl Pairing {
    /// Build a fresh pairing file. Returns the file plus the pairing secret,
    /// which the caller should drop immediately — it is recoverable from either
    /// code and never needs to be written down.
    pub fn create(daddy_code: &str, princess_code: &str) -> Result<(Self, [u8; 32]), String> {
        let salt: [u8; 16] = random();
        let secret: [u8; 32] = random();

        let mut wraps = Vec::with_capacity(2);
        for role in [Role::Daddy, Role::Princess] {
            let code = match role {
                Role::Daddy => daddy_code,
                Role::Princess => princess_code,
            };
            let key = argon2_key(code, &salt, ARGON2_M_KIB, ARGON2_T_COST, ARGON2_P_COST)?;
            let nonce: [u8; 12] = random();
            let ct = seal(&key, &nonce, &aad_for(role), &secret);
            wraps.push((nonce, ct));
        }

        let princess_wrap = wraps.pop().unwrap();
        let daddy_wrap = wraps.pop().unwrap();

        Ok((
            Pairing {
                m_kib: ARGON2_M_KIB,
                t_cost: ARGON2_T_COST,
                p_cost: ARGON2_P_COST,
                salt,
                wraps: [daddy_wrap, princess_wrap],
            },
            secret,
        ))
    }

    /// Try a typed code. One Argon2 pass, then two cheap AEAD trials — so the
    /// work does not depend on which role the code belongs to.
    pub fn unlock(&self, code: &str) -> Option<(Role, [u8; 32])> {
        let key = argon2_key(code, &self.salt, self.m_kib, self.t_cost, self.p_cost).ok()?;
        for role in [Role::Daddy, Role::Princess] {
            let (nonce, ct) = &self.wraps[role.tag() as usize];
            if let Some(plain) = open(&key, nonce, &aad_for(role), ct) {
                let secret: [u8; 32] = plain.as_slice().try_into().ok()?;
                return Some((role, secret));
            }
        }
        None
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(FILE_LEN);
        out.extend_from_slice(MAGIC);
        out.push(VERSION);
        out.extend_from_slice(&self.m_kib.to_be_bytes());
        out.extend_from_slice(&self.t_cost.to_be_bytes());
        out.extend_from_slice(&self.p_cost.to_be_bytes());
        out.extend_from_slice(&self.salt);
        for (nonce, ct) in &self.wraps {
            out.extend_from_slice(nonce);
            out.extend_from_slice(ct);
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != FILE_LEN {
            return Err(format!(
                "pairing file is {} bytes, expected {FILE_LEN}",
                bytes.len()
            ));
        }
        if &bytes[0..4] != MAGIC {
            return Err("pairing file has the wrong magic bytes".into());
        }
        if bytes[4] != VERSION {
            return Err(format!("unsupported pairing file version {}", bytes[4]));
        }
        let u32_at = |off: usize| u32::from_be_bytes(bytes[off..off + 4].try_into().unwrap());
        let m_kib = u32_at(5);
        let t_cost = u32_at(9);
        let p_cost = u32_at(13);
        let salt: [u8; 16] = bytes[17..33].try_into().unwrap();

        let mut wraps: Vec<([u8; 12], Vec<u8>)> = Vec::with_capacity(2);
        let mut off = 33;
        for _ in 0..2 {
            let nonce: [u8; 12] = bytes[off..off + 12].try_into().unwrap();
            let ct = bytes[off + 12..off + 12 + WRAP_LEN].to_vec();
            wraps.push((nonce, ct));
            off += 12 + WRAP_LEN;
        }
        let princess_wrap = wraps.pop().unwrap();
        let daddy_wrap = wraps.pop().unwrap();

        Ok(Pairing {
            m_kib,
            t_cost,
            p_cost,
            salt,
            wraps: [daddy_wrap, princess_wrap],
        })
    }
}
