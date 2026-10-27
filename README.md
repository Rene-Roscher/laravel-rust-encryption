# laravel-rust-encryption

[![CI](https://github.com/Rene-Roscher/laravel-rust-encryption/actions/workflows/ci.yml/badge.svg)](https://github.com/Rene-Roscher/laravel-rust-encryption/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/laravel-rust-encryption.svg)](https://crates.io/crates/laravel-rust-encryption)
[![docs.rs](https://docs.rs/laravel-rust-encryption/badge.svg)](https://docs.rs/laravel-rust-encryption)

A Rust port of Laravel's `Illuminate\Encryption\Encrypter`, **wire-compatible** with Laravel 10
through 13. Decrypt in Rust what Laravel encrypted with `Crypt` / `Encrypter`, and produce
payloads Laravel can decrypt, using the same key. It is the Rust sibling of
[laravel-go-encryption](https://github.com/Rene-Roscher/laravel-go-encryption) and
[laravel-node-encryption](https://github.com/Rene-Roscher/laravel-node-encryption).

## Features

- AES-128/256-CBC (Laravel's default is `aes-256-cbc`) **and** AES-128/256-GCM.
- Both Laravel paths: `encrypt_string` / `decrypt_string` (raw strings) and `encrypt` /
  `decrypt` (the PHP-`serialize` path: strings, numbers, bools, null, arrays and nested
  structures).
- Accepts the Laravel `APP_KEY` `base64:...` form, a bare base64 key, or raw key bytes.
- Key rotation: previous keys are tried on decryption, like `APP_PREVIOUS_KEYS` in Laravel 11+.
- Laravel's cookies (`EncryptCookies`), encrypted sessions and Eloquent `encrypted` casts, checked
  against the real Laravel classes.
- Constant-time MAC verification (CBC) and AEAD tag verification (GCM). Tampered, wrong-key and
  malformed payloads are always rejected with typed errors.
- Payload validation mirrors `Illuminate\Encryption\Encrypter`, including PHP's lenient
  `base64_decode` and `empty()` quirks.
- Built on [RustCrypto](https://github.com/RustCrypto); `#![forbid(unsafe_code)]`; keys zeroed on drop.
- Verified **in both directions** against the real Laravel encrypter in CI (Laravel 10 to 13).

## Install

```sh
cargo add laravel-rust-encryption
```

The minimum supported Rust version is 1.85.

## Usage

```rust
use laravel_rust_encryption::{Cipher, Encrypter};

fn main() -> Result<(), laravel_rust_encryption::Error> {
    // APP_KEY from the Laravel .env file: "base64:...."
    let app_key = std::env::var("APP_KEY").expect("APP_KEY is not set");
    let enc = Encrypter::from_app_key(&app_key, Cipher::Aes256Cbc)?;

    // Decrypt something Laravel encrypted (Crypt::encryptString(...) in PHP):
    let plain = enc.decrypt_string(&payload_from_laravel)?;

    // Encrypt something Laravel can decrypt (Crypt::decryptString($payload) in PHP):
    let payload = enc.encrypt_string("hello")?;
    Ok(())
}
```

On the Laravel side:

```php
use Illuminate\Support\Facades\Crypt;

$payload = Crypt::encryptString('hello');     // -> decrypt_string in Rust
$plain   = Crypt::decryptString($payloadFromRust);
```

`Encrypter::new` takes raw key bytes, like the PHP constructor. `Encrypter::from_app_key` takes
the string forms described under [Keys](#keys). The cipher must match `config('app.cipher')`
and is parsed from its name case-insensitively: `"AES-256-CBC".parse::<Cipher>()`.

### Structured values (the PHP-`serialize` path)

`encrypt` / `decrypt` mirror Laravel's default `Crypt::encrypt` / `Crypt::decrypt`, which
PHP-`serialize` the value:

```rust
use laravel_rust_encryption::Value;

let payload = enc.encrypt(&Value::map([
    ("user", Value::from("alice")),
    ("id", 7.into()),
    ("tags", Value::list(["x", "y"])),
]))?;
// PHP: Crypt::decrypt($payload) === ['user' => 'alice', 'id' => 7, 'tags' => ['x', 'y']]

let value = enc.decrypt(&payload_from_laravel_crypt_encrypt)?;
if let Some(user) = value.get("user").and_then(Value::as_str) {
    println!("{user}");
}
```

Decrypting untrusted payloads is safe with respect to PHP object injection: PHP **objects decode
to `Value::Object`** (class name and properties) and are never instantiated. They cannot be
encrypted again.

> For cross-language interop, a plain string carrying your own JSON (`encrypt_string` plus
> `serde_json`) is the simplest, least surprising option.

### Type mapping

| PHP (Laravel)                   | Rust                                                          |
|---------------------------------|---------------------------------------------------------------|
| `string`                        | `Value::String` (UTF-8) or `Value::Bytes` (anything else)     |
| `int`                           | `Value::Int(i64)`                                             |
| `float`                         | `Value::Float(f64)`                                           |
| `bool`                          | `Value::Bool`                                                 |
| `null`                          | `Value::Null`                                                 |
| `array` with keys `0..n`        | `Value::List`                                                 |
| `array` with any other keys     | `Value::Map(Vec<(Key, Value)>)`, in PHP order; `Key` is `Int` or `String` |
| `object`                        | `Value::Object { class, properties }` (decode-only)           |

The decoder never panics on any input and limits nesting to 128 levels. It rejects trailing data
and the PHP features that do not occur in `Crypt::encrypt` payloads of plain data: references
(`r:` / `R:`), enums (`E:`), `Serializable` objects (`C:`) and the escaped string form (`S:`).
Map keys and class names must be UTF-8.

For compile-time type safety, prefer the string path and let `serde` check your own types:

```rust
let payload = enc.encrypt_string(&serde_json::to_string(&config)?)?;
let config: Config = serde_json::from_str(&enc.decrypt_string(&payload)?)?;
```

### Keys

`parse_key` and `Encrypter::from_app_key` resolve a key string to raw bytes:

- `base64:XXXX` (the `APP_KEY` form) is base64-decoded.
- A bare base64 string that decodes to 16 or 32 bytes is decoded.
- Anything else is used as its raw bytes.

The forms cannot be confused: a raw key is exactly 16 or 32 bytes, its base64 form is 24 or 44
characters. The decoded key must have the length the cipher needs (16 bytes for `aes-128-*`,
32 for `aes-256-*`). `Encrypter::generate_key(cipher)` generates a random key, like
`php artisan key:generate`.

### Key rotation

Laravel 11 introduced `APP_PREVIOUS_KEYS`. Payloads are always encrypted with the current key,
and decryption falls back to the previous keys:

```rust
let enc = Encrypter::from_app_key(&app_key, Cipher::Aes256Cbc)?
    .with_previous_keys(old_app_keys.split(',').map(parse_key).collect::<Result<Vec<_>, _>>()?)?;
```

### Cookies, sessions and Eloquent casts

These Laravel features all sit on top of the encrypter. Each is verified against the real Laravel
classes in both directions.

**Cookies.** Laravel's `EncryptCookies` middleware encrypts `prefix + value` without
serialization, where the prefix binds the cookie to its name and the key. `encrypt_cookie` and
`decrypt_cookie` do the same; a cookie issued for another name, or by another application, is
`Error::InvalidCookie`. The prefix is also accepted for any previous key. Pass the raw cookie value,
URL-decoded if it comes from a `Cookie` header.

```rust
let cookie = enc.encrypt_cookie("laravel_session", &session_id)?;
let session_id = enc.decrypt_cookie("laravel_session", &cookie_from_laravel)?;
```

**Sessions.** With `session.encrypt` Laravel stores `Crypt::encrypt()` of the already serialized
attributes, so the payload decrypts to a string that holds the serialization (PHP's, or JSON with
`session.serialization = json`):

```rust
use laravel_rust_encryption::Value;

let Value::String(serialized) = enc.decrypt(&session_payload)? else { return };
let attributes = Value::from_php_serialized(&serialized)?;
let user_id = attributes.get("user_id").and_then(Value::as_i64);

// ...and the way back:
let payload = enc.encrypt(&Value::Bytes(attributes.to_php_serialized()?))?;
```

**Eloquent casts.** `encrypted` is `Crypt::encryptString()` of the value; `encrypted:array`,
`:object` and `:collection` encrypt its JSON. Use `decrypt_string` / `encrypt_string` and your JSON
library.

### Errors

Decryption errors mirror Laravel's `DecryptException` and use its messages, so a tampered
payload (`Error::InvalidMac`, `Error::Decrypt`) can be told apart from a malformed one
(`Error::InvalidPayload`). Further variants cover unsupported ciphers, bad keys, and invalid
PHP serialization or UTF-8 in the plaintext. `Error` is `#[non_exhaustive]`.

`decrypt_string` returns `Error::InvalidUtf8` for non-UTF-8 plaintext; `decrypt_bytes` and
`encrypt_bytes` handle arbitrary bytes, which PHP strings can hold.

`Encrypter::appears_encrypted(value)` checks whether a string has the shape of a payload without
decrypting it, like `Encrypter::appearsEncrypted` in Laravel.

## Wire format (identical to Laravel)

```
base64( json{ "iv": b64, "value": b64, "mac": hex, "tag": b64 } )
```

- **AES-CBC**: random 16-byte IV, PKCS#7 padding, `mac = HMAC-SHA256(base64(iv) + base64(value), key)`
  (lower-case hex), `tag = ""`.
- **AES-GCM**: random 12-byte IV, 16-byte GCM tag in `tag`, `mac = ""`.

The key is the raw key bytes. A Laravel `APP_KEY` `base64:XXXX` decodes to 32 bytes.

## Security

- CBC payloads are authenticated with HMAC-SHA256 and compared in constant time before
  decryption, so padding errors are never observable on unauthenticated data. GCM is
  authenticated by the AEAD tag.
- Any modification of the authenticated parts (`iv`, `value`, `mac` for CBC; `iv`, `value`,
  `tag` for GCM), a wrong key, an unsupported cipher or key length, or a malformed payload
  returns a typed error, never a silent or partial result.
- As in Laravel, the unused `tag` of a CBC payload and the unused `mac` of a GCM payload are not
  authenticated, and unknown JSON fields are ignored.
- Key material is zeroed on drop and never appears in `Debug` output. Plaintext returned to the
  caller is not zeroed.
- Decryption never panics on arbitrary input (covered by a mutation test).

## Compatibility

| Laravel | PHP  | Status                          |
|---------|------|---------------------------------|
| 13.x    | 8.3+ | tested in CI, both directions   |
| 12.x    | 8.2+ | tested in CI, both directions   |
| 11.x    | 8.2+ | tested in CI, both directions   |
| 10.x    | 8.1+ | tested in CI, both directions   |

Differences from the Go and Node.js packages: the Rust crate keeps PHP array order and
non-UTF-8 strings, supports previous keys, and does not read `APP_KEY` from the environment on
its own. Floats are written with the shortest digits that round-trip, as PHP does; in rare
cases where two such strings exist the last digit can differ from PHP's text, but both
represent the same `f64`.

## Testing

```sh
cargo test                                   # unit tests, Laravel-generated vectors, tamper tests
composer install                             # once, for the interop harness (needs PHP 8.2+)
php scripts/generate_vectors.php             # regenerate fixtures/vectors.json with real Laravel
php scripts/generate_app_vectors.php         # cookies, sessions, casts, random keys
cargo run --example genvectors | php scripts/verify_rust_vectors.php
cargo run --example mutations | php scripts/verify_mutations.php
```

`fixtures/vectors.json` holds payloads produced by the real `illuminate/encryption` (all four
ciphers, strings, serialized values, previous keys); `fixtures/app-vectors.json` holds random-key
payloads and what the real `EncryptCookies` logic, `EncryptedStore` and Eloquent casts produce. `tests/laravel_vectors.rs` decrypts them and
checks that re-serializing each decoded value reproduces PHP's `serialize()` output byte for
byte.

`examples/mutations.rs` emits valid and mutated payloads (edited fields, odd JSON types, broken
base64) with Rust's verdict on each; `scripts/verify_mutations.php` asks the real Laravel
encrypter about the same payloads, and both must accept and reject exactly the same ones and
return the same plaintext.

CI additionally runs, for Laravel 10, 11, 12 and 13, a fresh generation of those vectors
(**Laravel to Rust**), `scripts/verify_rust_vectors.php`, which decrypts what Rust encrypted
with the real Laravel encrypter (**Rust to Laravel**), and the mutation comparison.

## License

MIT © René Roscher
