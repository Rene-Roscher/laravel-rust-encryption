use std::fmt;
use std::str::FromStr;

use aes::{Aes128, Aes256};
use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes128Gcm, Aes256Gcm, Nonce, Tag};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use cbc::cipher::block_padding::Pkcs7;
use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::php::{self, Value};

const GCM_TAG_LEN: usize = 16;
const GCM_IV_LEN: usize = 12;
const CBC_IV_LEN: usize = 16;

/// A cipher supported by Laravel's encrypter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Cipher {
    /// `aes-128-cbc`
    Aes128Cbc,
    /// `aes-256-cbc`, Laravel's default.
    #[default]
    Aes256Cbc,
    /// `aes-128-gcm`
    Aes128Gcm,
    /// `aes-256-gcm`
    Aes256Gcm,
}

impl Cipher {
    /// The cipher's name as used in Laravel's `config/app.php`, in lower case.
    pub fn name(self) -> &'static str {
        match self {
            Cipher::Aes128Cbc => "aes-128-cbc",
            Cipher::Aes256Cbc => "aes-256-cbc",
            Cipher::Aes128Gcm => "aes-128-gcm",
            Cipher::Aes256Gcm => "aes-256-gcm",
        }
    }

    /// The key length this cipher requires, in bytes.
    pub fn key_size(self) -> usize {
        match self {
            Cipher::Aes128Cbc | Cipher::Aes128Gcm => 16,
            Cipher::Aes256Cbc | Cipher::Aes256Gcm => 32,
        }
    }

    /// Whether the cipher is authenticated by its own tag (GCM) instead of an HMAC (CBC).
    fn is_aead(self) -> bool {
        matches!(self, Cipher::Aes128Gcm | Cipher::Aes256Gcm)
    }

    fn iv_len(self) -> usize {
        if self.is_aead() {
            GCM_IV_LEN
        } else {
            CBC_IV_LEN
        }
    }
}

impl fmt::Display for Cipher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl FromStr for Cipher {
    type Err = Error;

    /// Parses a cipher name case-insensitively, so Laravel's `AES-256-CBC` works.
    fn from_str(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "aes-128-cbc" => Ok(Cipher::Aes128Cbc),
            "aes-256-cbc" => Ok(Cipher::Aes256Cbc),
            "aes-128-gcm" => Ok(Cipher::Aes128Gcm),
            "aes-256-gcm" => Ok(Cipher::Aes256Gcm),
            _ => Err(Error::UnsupportedCipher),
        }
    }
}

/// Resolves a key string, as found in a Laravel `.env` file, to raw key bytes.
///
/// - `base64:XXXX` (the `APP_KEY` form) is base64-decoded the way Laravel does, with PHP's
///   lenient `base64_decode`. Only an empty key is [`Error::InvalidKey`]; a malformed value
///   decodes to the wrong length, which [`Encrypter::new`] rejects.
/// - A bare base64 string that decodes to 16 or 32 bytes is decoded.
/// - Anything else is used as its raw bytes.
///
/// The three forms cannot be confused: a raw key has exactly 16 or 32 bytes, while the base64
/// of such a key is 24 or 44 characters long.
pub fn parse_key(key: &str) -> Result<Vec<u8>> {
    if key.is_empty() {
        return Err(Error::InvalidKey);
    }
    if let Some(encoded) = key.strip_prefix("base64:") {
        // Laravel uses PHP's lenient base64_decode here. A malformed value therefore yields
        // bytes of the wrong length, which the encrypter rejects.
        return Ok(php_base64_decode(encoded, false).unwrap_or_default());
    }
    match STANDARD.decode(key) {
        Ok(decoded) if matches!(decoded.len(), 16 | 32) => Ok(decoded),
        _ => Ok(key.as_bytes().to_vec()),
    }
}

/// A Laravel-compatible encrypter: Rust's `Illuminate\Encryption\Encrypter`.
///
/// Payloads are interchangeable with Laravel's `Crypt` facade for the same key and cipher.
/// The key material is zeroed when the encrypter is dropped, and [`Debug`](fmt::Debug)
/// never prints it.
#[derive(Clone)]
pub struct Encrypter {
    cipher: Cipher,
    key: Zeroizing<Vec<u8>>,
    previous_keys: Vec<Zeroizing<Vec<u8>>>,
}

impl fmt::Debug for Encrypter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Encrypter")
            .field("cipher", &self.cipher)
            .field("previous_keys", &self.previous_keys.len())
            .finish_non_exhaustive()
    }
}

impl Encrypter {
    /// Creates an encrypter from raw key bytes, which must match the cipher's
    /// [`key_size`](Cipher::key_size).
    pub fn new(key: &[u8], cipher: Cipher) -> Result<Self> {
        check_key_length(key, cipher)?;
        Ok(Self {
            cipher,
            key: Zeroizing::new(key.to_vec()),
            previous_keys: Vec::new(),
        })
    }

    /// Creates an encrypter from a key string in any form [`parse_key`] accepts, such as a
    /// Laravel `APP_KEY` (`base64:...`).
    pub fn from_app_key(key: &str, cipher: Cipher) -> Result<Self> {
        Self::new(&Zeroizing::new(parse_key(key)?), cipher)
    }

    /// Generates a random key for `cipher`, like `Encrypter::generateKey`.
    pub fn generate_key(cipher: Cipher) -> Result<Vec<u8>> {
        let mut key = vec![0u8; cipher.key_size()];
        getrandom::fill(&mut key).map_err(|_| Error::Encrypt)?;
        Ok(key)
    }

    /// Sets the keys tried when decrypting with the current key fails, like Laravel's
    /// `previousKeys()` and `APP_PREVIOUS_KEYS`. New payloads are always encrypted with the
    /// current key. Every key must match the cipher's key size.
    pub fn with_previous_keys<I, K>(mut self, keys: I) -> Result<Self>
    where
        I: IntoIterator<Item = K>,
        K: AsRef<[u8]>,
    {
        let mut previous = Vec::new();
        for key in keys {
            check_key_length(key.as_ref(), self.cipher)?;
            previous.push(Zeroizing::new(key.as_ref().to_vec()));
        }
        self.previous_keys = previous;
        Ok(self)
    }

    /// The cipher in use.
    pub fn cipher(&self) -> Cipher {
        self.cipher
    }

    /// The current raw key.
    pub fn key(&self) -> &[u8] {
        &self.key
    }

    /// Encrypts a value after PHP-serializing it, like `Crypt::encrypt($value)`.
    /// Laravel's `Crypt::decrypt($payload)` returns the original value.
    pub fn encrypt(&self, value: &Value) -> Result<String> {
        self.encrypt_bytes(&php::serialize(value)?)
    }

    /// Decrypts a payload and PHP-unserializes it, like `Crypt::decrypt($payload)`.
    pub fn decrypt(&self, payload: &str) -> Result<Value> {
        php::unserialize(&self.decrypt_bytes(payload)?)
    }

    /// Encrypts a string without serialization, like `Crypt::encryptString($value)`.
    pub fn encrypt_string(&self, plaintext: &str) -> Result<String> {
        self.encrypt_bytes(plaintext.as_bytes())
    }

    /// Decrypts a payload to a string without unserialization, like
    /// `Crypt::decryptString($payload)`. Fails with [`Error::InvalidUtf8`] if the plaintext is
    /// not UTF-8.
    pub fn decrypt_string(&self, payload: &str) -> Result<String> {
        String::from_utf8(self.decrypt_bytes(payload)?).map_err(|_| Error::InvalidUtf8)
    }

    /// Like [`encrypt_string`](Self::encrypt_string) for arbitrary bytes, which PHP strings
    /// can hold.
    pub fn encrypt_bytes(&self, plaintext: &[u8]) -> Result<String> {
        let mut iv = vec![0u8; self.cipher.iv_len()];
        getrandom::fill(&mut iv).map_err(|_| Error::Encrypt)?;

        let (value, tag) = match self.cipher {
            Cipher::Aes128Cbc => (
                cbc::Encryptor::<Aes128>::new_from_slices(&self.key, &iv)
                    .map_err(|_| Error::Encrypt)?
                    .encrypt_padded_vec_mut::<Pkcs7>(plaintext),
                Vec::new(),
            ),
            Cipher::Aes256Cbc => (
                cbc::Encryptor::<Aes256>::new_from_slices(&self.key, &iv)
                    .map_err(|_| Error::Encrypt)?
                    .encrypt_padded_vec_mut::<Pkcs7>(plaintext),
                Vec::new(),
            ),
            Cipher::Aes128Gcm => gcm_encrypt::<Aes128Gcm>(&self.key, &iv, plaintext)?,
            Cipher::Aes256Gcm => gcm_encrypt::<Aes256Gcm>(&self.key, &iv, plaintext)?,
        };

        let iv = STANDARD.encode(iv);
        let value = STANDARD.encode(value);
        let tag = STANDARD.encode(tag);
        let mac = if self.cipher.is_aead() {
            String::new()
        } else {
            hex(&hash(&iv, &value, &self.key))
        };

        // Same field order and unescaped slashes as Laravel's json_encode call. All values are
        // base64 or hex, so no JSON escaping is needed.
        let json = format!(r#"{{"iv":"{iv}","value":"{value}","mac":"{mac}","tag":"{tag}"}}"#);
        Ok(STANDARD.encode(json))
    }

    /// Like [`decrypt_string`](Self::decrypt_string) but returns the plaintext bytes.
    pub fn decrypt_bytes(&self, payload: &str) -> Result<Vec<u8>> {
        let p = self.parse_payload(payload)?;

        // Like Laravel, try the current key first and then the previous keys.
        let keys = self.all_keys();

        if self.cipher.is_aead() {
            let tag = p.tag.as_deref().ok_or(Error::Decrypt)?;
            if tag.len() != GCM_TAG_LEN {
                return Err(Error::Decrypt);
            }
            for key in keys {
                if let Some(plain) = self.gcm_decrypt(key, &p.iv, &p.value, tag) {
                    return Ok(plain);
                }
            }
            return Err(Error::Decrypt);
        }

        // CBC: authenticate before decrypting; only the key whose MAC matches is used.
        if p.tag.is_some() {
            return Err(Error::Decrypt);
        }
        let key = keys
            .into_iter()
            .find(|key| {
                let expected = hex(&hash(&p.iv_b64, &p.value_b64, key));
                bool::from(expected.as_bytes().ct_eq(p.mac.as_bytes()))
            })
            .ok_or(Error::InvalidMac)?;
        self.cbc_decrypt(key, &p.iv, &p.value)
    }

    /// Encrypts a cookie value the way Laravel's `EncryptCookies` middleware does: the value is
    /// prefixed with an HMAC of the cookie name and the key, and encrypted without
    /// serialization. Laravel decrypts it back to `value` for the cookie `name`.
    pub fn encrypt_cookie(&self, name: &str, value: &str) -> Result<String> {
        let mut plain = cookie_prefix(name, &self.key).into_bytes();
        plain.extend_from_slice(value.as_bytes());
        self.encrypt_bytes(&plain)
    }

    /// Decrypts a cookie that Laravel's `EncryptCookies` middleware encrypted, and checks that
    /// it was issued for the cookie `name` by this application: the prefix must match the
    /// current key or one of the previous keys, otherwise the result is
    /// [`Error::InvalidCookie`] (Laravel treats such a cookie as absent).
    ///
    /// The payload is the raw cookie value; URL-decode it first if it comes from a
    /// `Cookie` header. Cookies that an application serializes on purpose
    /// (`EncryptCookies::serialized()`) are not supported.
    pub fn decrypt_cookie(&self, name: &str, payload: &str) -> Result<String> {
        let plain = self.decrypt_bytes(payload)?;
        for key in self.all_keys() {
            let prefix = cookie_prefix(name, key);
            if plain.len() >= prefix.len()
                && bool::from(plain[..prefix.len()].ct_eq(prefix.as_bytes()))
            {
                return String::from_utf8(plain[prefix.len()..].to_vec())
                    .map_err(|_| Error::InvalidUtf8);
            }
        }
        Err(Error::InvalidCookie)
    }

    /// The current key followed by the previous keys, like `getAllKeys()`.
    fn all_keys(&self) -> impl Iterator<Item = &Zeroizing<Vec<u8>>> {
        std::iter::once(&self.key).chain(&self.previous_keys)
    }

    /// Whether `value` looks like a payload produced by an encrypter, without decrypting it
    /// (Laravel's `Encrypter::appearsEncrypted`).
    pub fn appears_encrypted(value: &str) -> bool {
        let Some(decoded) = php_base64_decode(value, true) else {
            return false;
        };
        match serde_json::from_slice::<serde_json::Value>(&decoded) {
            Ok(serde_json::Value::Object(o)) => ["iv", "value", "mac"]
                .iter()
                .all(|k| o.get(*k).is_some_and(|v| !v.is_null())),
            _ => false,
        }
    }

    fn parse_payload(&self, payload: &str) -> Result<Payload> {
        // Laravel: json_decode(base64_decode($payload), true)
        let json = php_base64_decode(payload, false).ok_or(Error::InvalidPayload)?;
        let json: serde_json::Value =
            serde_json::from_slice(&json).map_err(|_| Error::InvalidPayload)?;
        let obj = json.as_object().ok_or(Error::InvalidPayload)?;

        let field = |name: &str| -> Result<String> {
            match obj.get(name) {
                Some(serde_json::Value::String(s)) => Ok(s.clone()),
                _ => Err(Error::InvalidPayload),
            }
        };
        let iv_b64 = field("iv")?;
        let value_b64 = field("value")?;
        let mac = field("mac")?;
        let tag_b64 = match obj.get("tag") {
            None | Some(serde_json::Value::Null) => String::new(),
            Some(serde_json::Value::String(s)) => s.clone(),
            Some(_) => return Err(Error::InvalidPayload),
        };

        let iv = php_base64_decode(&iv_b64, true)
            .filter(|iv| iv.len() == self.cipher.iv_len())
            .ok_or(Error::InvalidPayload)?;
        // openssl_decrypt() base64-decodes the value leniently.
        let value = php_base64_decode(&value_b64, false).ok_or(Error::InvalidPayload)?;
        // PHP's empty() treats "0" like "", so Laravel sees neither as a tag.
        let tag = if tag_b64.is_empty() || tag_b64 == "0" {
            None
        } else {
            php_base64_decode(&tag_b64, false)
        };

        Ok(Payload {
            iv_b64,
            value_b64,
            mac,
            iv,
            value,
            tag,
        })
    }

    fn cbc_decrypt(&self, key: &[u8], iv: &[u8], value: &[u8]) -> Result<Vec<u8>> {
        match self.cipher {
            Cipher::Aes128Cbc => cbc::Decryptor::<Aes128>::new_from_slices(key, iv)
                .map_err(|_| Error::Decrypt)?
                .decrypt_padded_vec_mut::<Pkcs7>(value)
                .map_err(|_| Error::Decrypt),
            _ => cbc::Decryptor::<Aes256>::new_from_slices(key, iv)
                .map_err(|_| Error::Decrypt)?
                .decrypt_padded_vec_mut::<Pkcs7>(value)
                .map_err(|_| Error::Decrypt),
        }
    }

    fn gcm_decrypt(&self, key: &[u8], iv: &[u8], value: &[u8], tag: &[u8]) -> Option<Vec<u8>> {
        match self.cipher {
            Cipher::Aes128Gcm => gcm_decrypt::<Aes128Gcm>(key, iv, value, tag),
            _ => gcm_decrypt::<Aes256Gcm>(key, iv, value, tag),
        }
    }
}

struct Payload {
    /// The base64 strings as sent; the MAC covers these, not the decoded bytes.
    iv_b64: String,
    value_b64: String,
    mac: String,
    iv: Vec<u8>,
    value: Vec<u8>,
    tag: Option<Vec<u8>>,
}

/// PHP's `base64_decode($input, $strict)`.
///
/// Non-strict mode skips every character outside the alphabet (including `=` and
/// whitespace) and never fails. Strict mode skips only whitespace, fails on other invalid
/// characters or data after padding, on a dangling sixth bit, and on wrong padding, but
/// accepts missing padding. Laravel relies on both modes.
fn php_base64_decode(input: &str, strict: bool) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(input.len() / 4 * 3 + 3);
    let (mut acc, mut count, mut padding) = (0u32, 0usize, 0usize);

    for &c in input.as_bytes() {
        if c == b'=' {
            padding += 1;
            continue;
        }
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'\t' | b'\n' | b'\r' | b' ' => continue,
            _ if strict => return None,
            _ => continue,
        };
        if strict && padding > 0 {
            return None;
        }
        acc = (acc << 6) | u32::from(v);
        count += 1;
        if count % 4 == 0 {
            out.extend_from_slice(&[(acc >> 16) as u8, (acc >> 8) as u8, acc as u8]);
            acc = 0;
        }
    }

    // A trailing group of 2 or 3 characters yields 1 or 2 bytes; 1 character yields none.
    match count % 4 {
        2 => out.push((acc >> 4) as u8),
        3 => out.extend_from_slice(&[(acc >> 10) as u8, (acc >> 2) as u8]),
        _ => {}
    }
    if strict {
        if count % 4 == 1 {
            return None;
        }
        if padding > 0 && (padding > 2 || (count + padding) % 4 != 0) {
            return None;
        }
    }
    Some(out)
}

fn check_key_length(key: &[u8], cipher: Cipher) -> Result<()> {
    if key.len() == cipher.key_size() {
        Ok(())
    } else {
        Err(Error::InvalidKeyLength {
            expected: cipher.key_size(),
            actual: key.len(),
        })
    }
}

/// Laravel's MAC: `hash_hmac('sha256', $iv.$value, $key)` over the base64 strings.
fn hash(iv_b64: &str, value_b64: &str, key: &[u8]) -> Vec<u8> {
    // HMAC accepts keys of any length.
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(iv_b64.as_bytes());
    mac.update(value_b64.as_bytes());
    mac.finalize().into_bytes().to_vec()
}

/// Laravel's `CookieValuePrefix::create()`: `hash_hmac('sha1', $name.'v2', $key).'|'`.
fn cookie_prefix(name: &str, key: &[u8]) -> String {
    let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(name.as_bytes());
    mac.update(b"v2");
    format!("{}|", hex(&mac.finalize().into_bytes()))
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(DIGITS[usize::from(b >> 4)] as char);
        out.push(DIGITS[usize::from(b & 0x0f)] as char);
    }
    out
}

fn gcm_encrypt<C: AeadInPlace + KeyInit>(
    key: &[u8],
    iv: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, Vec<u8>)> {
    let cipher = C::new_from_slice(key).map_err(|_| Error::Encrypt)?;
    let mut buf = plaintext.to_vec();
    let tag = cipher
        .encrypt_in_place_detached(Nonce::from_slice(iv), b"", &mut buf)
        .map_err(|_| Error::Encrypt)?;
    Ok((buf, tag.to_vec()))
}

fn gcm_decrypt<C: AeadInPlace + KeyInit>(
    key: &[u8],
    iv: &[u8],
    value: &[u8],
    tag: &[u8],
) -> Option<Vec<u8>> {
    let cipher = C::new_from_slice(key).ok()?;
    let mut buf = value.to_vec();
    cipher
        .decrypt_in_place_detached(Nonce::from_slice(iv), b"", &mut buf, Tag::from_slice(tag))
        .ok()?;
    Some(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Expected values are PHP's `base64_decode($s, true)` and `base64_decode($s)`.
    #[test]
    fn base64_decoding_matches_php() {
        // (input, strict result, non-strict result)
        type Case<'a> = (&'a str, Option<&'a [u8]>, &'a [u8]);
        let cases: [Case; 24] = [
            ("", Some(b""), b""),
            ("A", None, b""),
            ("AA", Some(b"\x00"), b"\x00"),
            ("AAAA", Some(b"\x00\x00\x00"), b"\x00\x00\x00"),
            ("QQ==", Some(b"A"), b"A"),
            ("QQ=", None, b"A"),
            ("QQ", Some(b"A"), b"A"),
            ("Q", None, b""),
            ("QUJD", Some(b"ABC"), b"ABC"),
            ("QU JD", Some(b"ABC"), b"ABC"),
            ("QUJD=", None, b"ABC"),
            ("QUJD====", None, b"ABC"),
            ("QQ==QQ==", None, b"A\x04\x10"),
            ("QQ=Q", None, b"A\x04"),
            ("Q=Q=", None, b"A"),
            ("QR==", Some(b"A"), b"A"),
            ("QUJ*", None, b"AB"),
            ("!!", None, b""),
            ("A=", None, b""),
            ("AA=", None, b"\x00"),
            ("AAA==", None, b"\x00\x00"),
            ("====", None, b""),
            ("QUI=\n", Some(b"AB"), b"AB"),
            ("Zm9v\nYmFy", Some(b"foobar"), b"foobar"),
        ];
        for (input, strict, loose) in cases {
            assert_eq!(
                php_base64_decode(input, true).as_deref(),
                strict,
                "strict {input:?}"
            );
            assert_eq!(
                php_base64_decode(input, false).as_deref(),
                Some(loose),
                "loose {input:?}"
            );
        }
    }

    #[test]
    fn base64_decoding_agrees_with_the_base64_crate_on_canonical_input() {
        for len in 0..40 {
            let data: Vec<u8> = (0..len).map(|i| (i * 37 + 11) as u8).collect();
            let encoded = STANDARD.encode(&data);
            assert_eq!(php_base64_decode(&encoded, true), Some(data.clone()));
            assert_eq!(php_base64_decode(&encoded, false), Some(data));
        }
    }
}
