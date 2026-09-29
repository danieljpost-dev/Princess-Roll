//! Princess-Roll — peer-to-peer encrypted chat and a shared D20.
//!
//! There is no server. The page is static, the two browsers talk directly over
//! WebRTC, and every payload is sealed with a key that exists only in memory
//! for the life of the tab. Nothing is written to localStorage, sessionStorage,
//! IndexedDB or cookies, and no request leaves the page except to public STUN
//! servers while the connection is being established.

pub mod crypto;
pub mod dice;
pub mod pairing;
pub mod protocol;
pub mod signal;

/// Opt-in: `cargo test --features tests`. Without the feature this module does
/// not exist, so no test code can reach a release artifact.
#[cfg(all(test, feature = "tests"))]
mod tests;

#[cfg(target_arch = "wasm32")]
mod app;
#[cfg(target_arch = "wasm32")]
mod audio;
#[cfg(target_arch = "wasm32")]
mod render;
#[cfg(target_arch = "wasm32")]
mod rtc;

#[cfg(target_arch = "wasm32")]
pub use app::start;
