//! Interop Envelope v1: a JSON document with a scope, timestamps and data, encrypted with
//! `encrypt_string`. The encryption authenticates it, so neither the scope nor the timestamps
//! can be changed without the key. The `rene-roscher/laravel-interop` package for Laravel, and the
//! Go and Node.js packages, read and write the same format.
//!
//! ```
//! use laravel_rust_encryption::{Cipher, Encrypter, Expiry};
//! use std::time::Duration;
//!
//! let enc = Encrypter::new(&[0x2b; 32], Cipher::Aes256Cbc)?;
//! let token = enc.seal_envelope("password-reset", &serde_json::json!({"user": 7}), Expiry::In(Duration::from_secs(3600)))?;
//!
//! let opened = enc.open_envelope(&token, "password-reset")?;
//! assert_eq!(opened.data["user"], 7);
//! assert!(enc.open_envelope(&token, "invite").is_err()); // another scope
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! The plaintext is `{"typ":"env","v":1,"iat":…,"nbf":…,"exp":…,"scope":…,"data":…}`. Opening
//! checks, in this order, and the first failure wins: the structure, the version, the scope,
//! `nbf` and `exp`. A token is valid for `nbf - leeway <= now < exp + leeway`.

use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use serde_json::Value as Json;

use crate::{Encrypter, Error};

const TYPE: &str = "env";
const VERSION: i64 = 1;

/// When an envelope stops being valid. Sealing requires an explicit choice, so that a token never
/// lives forever by accident.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expiry {
    /// Valid for this long after it is sealed. Must be at least one second.
    In(Duration),
    /// Valid until this Unix timestamp (seconds, UTC).
    At(i64),
    /// Never expires. Prefer a lifetime unless the scope itself limits the token.
    Never,
}

/// Options for [`Encrypter::seal_envelope_with`].
#[derive(Debug, Clone, Copy, Default)]
pub struct SealOptions {
    not_before: Option<i64>,
    now: Option<i64>,
}

impl SealOptions {
    /// The envelope is not valid before this Unix timestamp.
    pub fn not_before(mut self, timestamp: i64) -> Self {
        self.not_before = Some(timestamp);
        self
    }

    /// Overrides the current time (Unix seconds), for tests.
    pub fn now(mut self, timestamp: i64) -> Self {
        self.now = Some(timestamp);
        self
    }
}

/// Options for [`Encrypter::open_envelope_with`].
#[derive(Debug, Clone, Copy, Default)]
pub struct OpenOptions {
    leeway: i64,
    now: Option<i64>,
}

impl OpenOptions {
    /// Seconds of clock difference to tolerate on both time checks. Defaults to 0.
    pub fn leeway(mut self, seconds: u32) -> Self {
        self.leeway = i64::from(seconds);
        self
    }

    /// Overrides the current time (Unix seconds), for tests.
    pub fn now(mut self, timestamp: i64) -> Self {
        self.now = Some(timestamp);
        self
    }
}

/// A verified envelope.
#[derive(Debug, Clone, PartialEq)]
pub struct Opened {
    /// The scope it was sealed for (the one that was asked for).
    pub scope: String,
    /// The sealed data.
    pub data: Json,
    /// When it was sealed, Unix seconds.
    pub issued_at: i64,
    /// Not valid before this time, if set.
    pub not_before: Option<i64>,
    /// Not valid from this time on, if set.
    pub expires_at: Option<i64>,
}

impl Opened {
    /// Deserializes the data into `T`.
    pub fn into_data<T: serde::de::DeserializeOwned>(self) -> Result<T, serde_json::Error> {
        serde_json::from_value(self.data)
    }
}

/// Why an envelope could not be sealed or opened.
#[derive(Debug)]
#[non_exhaustive]
pub enum EnvelopeError {
    /// The payload could not be decrypted (wrong key, tampering, malformed payload).
    Decrypt(Error),
    /// Not a valid envelope: not a JSON object, `typ` is not `"env"`, or a field is missing or has
    /// the wrong type.
    Invalid,
    /// The envelope has a version this crate does not read.
    UnsupportedVersion,
    /// The envelope was sealed for another scope.
    ScopeMismatch,
    /// `nbf` is still in the future.
    NotYetValid,
    /// `exp` has passed.
    Expired,
    /// The scope is empty, the lifetime is shorter than a second, or the expiry is not a positive
    /// timestamp.
    InvalidArgument(&'static str),
    /// The data could not be serialized.
    Serialize(serde_json::Error),
}

impl EnvelopeError {
    /// The verdict name shared by all implementations: `decrypt_error`, `invalid`,
    /// `unsupported_version`, `scope_mismatch`, `not_yet_valid` or `expired`.
    pub fn kind(&self) -> &'static str {
        match self {
            EnvelopeError::Decrypt(_) => "decrypt_error",
            EnvelopeError::UnsupportedVersion => "unsupported_version",
            EnvelopeError::ScopeMismatch => "scope_mismatch",
            EnvelopeError::NotYetValid => "not_yet_valid",
            EnvelopeError::Expired => "expired",
            EnvelopeError::Invalid
            | EnvelopeError::InvalidArgument(_)
            | EnvelopeError::Serialize(_) => "invalid",
        }
    }
}

impl fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EnvelopeError::Decrypt(e) => e.fmt(f),
            EnvelopeError::Invalid => f.write_str("The payload is not a valid envelope."),
            EnvelopeError::UnsupportedVersion => {
                f.write_str("The envelope version is not supported.")
            }
            EnvelopeError::ScopeMismatch => {
                f.write_str("The envelope was issued for another scope.")
            }
            EnvelopeError::NotYetValid => f.write_str("The envelope is not valid yet."),
            EnvelopeError::Expired => f.write_str("The envelope has expired."),
            EnvelopeError::InvalidArgument(why) => f.write_str(why),
            EnvelopeError::Serialize(e) => write!(f, "The data cannot be serialized: {e}"),
        }
    }
}

impl std::error::Error for EnvelopeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            EnvelopeError::Decrypt(e) => Some(e),
            EnvelopeError::Serialize(e) => Some(e),
            _ => None,
        }
    }
}

impl From<Error> for EnvelopeError {
    fn from(e: Error) -> Self {
        EnvelopeError::Decrypt(e)
    }
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

impl Encrypter {
    /// Seals `data` for `scope`; see the [module documentation](self).
    pub fn seal_envelope<T: Serialize>(
        &self,
        scope: &str,
        data: &T,
        expiry: Expiry,
    ) -> Result<String, EnvelopeError> {
        self.seal_envelope_with(scope, data, expiry, SealOptions::default())
    }

    /// Like [`seal_envelope`](Self::seal_envelope) with a start time and a clock override.
    pub fn seal_envelope_with<T: Serialize>(
        &self,
        scope: &str,
        data: &T,
        expiry: Expiry,
        options: SealOptions,
    ) -> Result<String, EnvelopeError> {
        if scope.is_empty() {
            return Err(EnvelopeError::InvalidArgument(
                "The scope must not be empty.",
            ));
        }
        let now = options.now.unwrap_or_else(unix_now);
        let exp = match expiry {
            Expiry::In(lifetime) => {
                let seconds = i64::try_from(lifetime.as_secs()).unwrap_or(i64::MAX);
                if seconds < 1 {
                    return Err(EnvelopeError::InvalidArgument(
                        "The lifetime must be at least one second.",
                    ));
                }
                Some(now.saturating_add(seconds))
            }
            Expiry::At(timestamp) if timestamp > 0 => Some(timestamp),
            Expiry::At(_) => {
                return Err(EnvelopeError::InvalidArgument(
                    "The expiry must be a positive Unix timestamp.",
                ))
            }
            Expiry::Never => None,
        };

        let nbf = options
            .not_before
            .map_or_else(String::new, |t| format!(r#""nbf":{t},"#));
        let exp = exp.map_or_else(String::new, |t| format!(r#""exp":{t},"#));
        let scope = serde_json::to_string(scope).map_err(EnvelopeError::Serialize)?;
        let data = serde_json::to_string(data).map_err(EnvelopeError::Serialize)?;
        let document = format!(
            r#"{{"typ":"{TYPE}","v":{VERSION},"iat":{now},{nbf}{exp}"scope":{scope},"data":{data}}}"#
        );
        Ok(self.encrypt_string(&document)?)
    }

    /// Opens an envelope sealed for `scope`; see the [module documentation](self).
    pub fn open_envelope(&self, token: &str, scope: &str) -> Result<Opened, EnvelopeError> {
        self.open_envelope_with(token, scope, OpenOptions::default())
    }

    /// Like [`open_envelope`](Self::open_envelope) with a leeway and a clock override.
    pub fn open_envelope_with(
        &self,
        token: &str,
        scope: &str,
        options: OpenOptions,
    ) -> Result<Opened, EnvelopeError> {
        let plaintext = self.decrypt_bytes(token)?;
        let document: Json = std::str::from_utf8(&plaintext)
            .ok()
            .and_then(|text| serde_json::from_str(text).ok())
            .ok_or(EnvelopeError::Invalid)?;
        let Json::Object(fields) = document else {
            return Err(EnvelopeError::Invalid);
        };
        if fields.get("typ").and_then(Json::as_str) != Some(TYPE) {
            return Err(EnvelopeError::Invalid);
        }

        if timestamp(fields.get("v"), true)? != Some(VERSION) {
            return Err(EnvelopeError::UnsupportedVersion);
        }
        let issued_at = timestamp(fields.get("iat"), true)?.ok_or(EnvelopeError::Invalid)?;
        let not_before = timestamp(fields.get("nbf"), false)?;
        let expires_at = timestamp(fields.get("exp"), false)?;
        let sealed_scope = match fields.get("scope") {
            Some(Json::String(s)) if !s.is_empty() => s,
            _ => return Err(EnvelopeError::Invalid),
        };
        let data = fields.get("data").ok_or(EnvelopeError::Invalid)?;

        if sealed_scope != scope {
            return Err(EnvelopeError::ScopeMismatch);
        }

        let now = options.now.unwrap_or_else(unix_now);
        if not_before.is_some_and(|nbf| now < nbf.saturating_sub(options.leeway)) {
            return Err(EnvelopeError::NotYetValid);
        }
        if expires_at.is_some_and(|exp| now >= exp.saturating_add(options.leeway)) {
            return Err(EnvelopeError::Expired);
        }

        Ok(Opened {
            scope: sealed_scope.clone(),
            data: data.clone(),
            issued_at,
            not_before,
            expires_at,
        })
    }
}

/// Reads a version or timestamp field. Any JSON number without a fractional part is accepted,
/// because JavaScript cannot tell `1` from `1.0`; everything else is invalid. An absent optional
/// field is `None`.
fn timestamp(value: Option<&Json>, required: bool) -> Result<Option<i64>, EnvelopeError> {
    let Some(value) = value else {
        return if required {
            Err(EnvelopeError::Invalid)
        } else {
            Ok(None)
        };
    };
    let Json::Number(n) = value else {
        return Err(EnvelopeError::Invalid);
    };
    if let Some(i) = n.as_i64() {
        return Ok(Some(i));
    }
    match n.as_f64() {
        Some(f) if f.is_finite() && f.fract() == 0.0 && f.abs() < 9_007_199_254_740_992.0 => {
            Ok(Some(f as i64))
        }
        _ => Err(EnvelopeError::Invalid),
    }
}
