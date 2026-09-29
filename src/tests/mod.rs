//! The test suite.
//!
//! Gated in lib.rs behind `all(test, feature = "tests")`, so a default build —
//! including the WASM the page ships — never compiles any of it.
//!
//! Kept out of the implementation files so each of those reads as the thing it
//! is, and so the suite can be reviewed as a whole.

mod crypto;
mod dice;
mod pairing;
mod protocol;
mod signal;
