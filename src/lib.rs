//! SeePass core: everything except the user interface.
//!
//! * [`crypto`] – the on-disk format (Argon2id + XChaCha20-Poly1305).
//! * [`vault`] – an unlocked vault and its entries, atomic saves, backups, merge.
//! * [`generator`] / [`strength`] – password generation and zxcvbn scoring.
//! * [`settings`] – non-secret preferences and file locations.
//! * [`install`] – the install folder and self-install on Linux/macOS.

pub mod crypto;
pub mod error;
pub mod generator;
pub mod install;
pub mod settings;
pub mod strength;
pub mod vault;

pub use error::{Error, Result};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
