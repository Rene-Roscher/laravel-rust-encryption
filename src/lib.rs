//! A Rust port of Laravel's `Illuminate\Encryption\Encrypter`, wire-compatible with Laravel
//! 10 through 13.
//!
//! Decrypt in Rust what Laravel encrypted with `Crypt` / `Encrypter`, and produce payloads
//! Laravel can decrypt, using the same key.
//!
//! ```
//! use laravel_rust_encryption::{Cipher, Encrypter};
//!
//! // A Laravel `APP_KEY`; use `std::env::var("APP_KEY")` in an application.
//! let app_key = "base64:KysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKys=";
//! let enc = Encrypter::from_app_key(app_key, Cipher::Aes256Cbc)?;
//!
//! // Crypt::encryptString / Crypt::decryptString
//! let payload = enc.encrypt_string("hello")?;
//! assert_eq!(enc.decrypt_string(&payload)?, "hello");
//! # Ok::<(), laravel_rust_encryption::Error>(())
//! ```
//!
//! The payload is `base64(json{"iv", "value", "mac", "tag"})`:
//!
//! - **AES-CBC**: random 16-byte IV, PKCS#7 padding, `mac` = lower-case hex
//!   `HMAC-SHA256(base64(iv) + base64(value), key)`, `tag` empty.
//! - **AES-GCM**: random 12-byte IV, the 16-byte tag in `tag`, `mac` empty.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod encrypter;
mod error;
mod php;

pub use encrypter::{parse_key, Cipher, Encrypter};
pub use error::{Error, Result};
pub use php::{Key, Value};
