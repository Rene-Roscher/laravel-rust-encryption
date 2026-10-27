use std::fmt;

/// Result type used throughout the crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors returned by [`Encrypter`](crate::Encrypter).
///
/// The decryption variants mirror the cases of Laravel's `DecryptException`, so a tampered
/// payload ([`InvalidMac`](Error::InvalidMac), [`Decrypt`](Error::Decrypt)) can be told
/// apart from a malformed one ([`InvalidPayload`](Error::InvalidPayload)). The messages are
/// Laravel's.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The cipher name is not one of `aes-128-cbc`, `aes-256-cbc`, `aes-128-gcm` or
    /// `aes-256-gcm`.
    UnsupportedCipher,
    /// The key is empty.
    InvalidKey,
    /// The key does not have the length the cipher requires.
    InvalidKeyLength {
        /// Key length required by the cipher, in bytes.
        expected: usize,
        /// Length of the key that was given, in bytes.
        actual: usize,
    },
    /// The payload is not a valid Laravel payload (bad base64 or JSON, missing fields, wrong
    /// IV length).
    InvalidPayload,
    /// The HMAC of a CBC payload does not match (tampered payload or wrong key).
    InvalidMac,
    /// The data could not be decrypted (bad GCM tag, wrong key, bad padding, or a tag where
    /// the cipher does not use one).
    Decrypt,
    /// The data could not be encrypted.
    Encrypt,
    /// The decrypted plaintext is not valid PHP `serialize()` output, or uses a feature this
    /// crate does not decode.
    Unserialize,
    /// The value cannot be PHP-serialized (see [`Value::Object`](crate::Value::Object)).
    Serialize,
    /// A decrypted cookie does not start with the prefix Laravel adds for its name and key, so
    /// it was not issued for this cookie (or by this application).
    InvalidCookie,
    /// The decrypted plaintext is not valid UTF-8; use
    /// [`Encrypter::decrypt_bytes`](crate::Encrypter::decrypt_bytes).
    InvalidUtf8,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::UnsupportedCipher => f.write_str(
                "Unsupported cipher. Supported ciphers are: aes-128-cbc, aes-256-cbc, \
                 aes-128-gcm, aes-256-gcm.",
            ),
            Error::InvalidKey => f.write_str("The encryption key is empty."),
            Error::InvalidKeyLength { expected, actual } => write!(
                f,
                "Incorrect key length for the cipher: expected {expected} bytes, got {actual}."
            ),
            Error::InvalidPayload => f.write_str("The payload is invalid."),
            Error::InvalidMac => f.write_str("The MAC is invalid."),
            Error::Decrypt => f.write_str("Could not decrypt the data."),
            Error::Encrypt => f.write_str("Could not encrypt the data."),
            Error::Unserialize => f.write_str("The decrypted data is not valid PHP serialization."),
            Error::Serialize => f.write_str("The value cannot be PHP-serialized."),
            Error::InvalidCookie => f.write_str("The cookie value prefix is invalid."),
            Error::InvalidUtf8 => f.write_str("The decrypted data is not valid UTF-8."),
        }
    }
}

impl std::error::Error for Error {}
