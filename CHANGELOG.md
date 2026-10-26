# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-10-26

### Added
- Initial release: `Encrypter` with `encrypt_string` / `decrypt_string` (and byte variants),
  wire-compatible with Laravel's `Illuminate\Encryption\Encrypter` (AES-128/256-CBC and
  AES-128/256-GCM), Laravel 10 to 13.
- `encrypt` / `decrypt` (the PHP-`serialize` path) with a built-in PHP serializer for null,
  bool, ints, floats, strings, lists and maps; PHP objects decode to `Value::Object` and are
  never instantiated.
- `base64:` / bare-base64 / raw key parsing via `Encrypter::from_app_key` and `parse_key`.
- Previous keys (`with_previous_keys`), as in Laravel 11+.
- Constant-time MAC verification (CBC) and AEAD tag verification (GCM); tampered, wrong-key,
  and malformed payloads are always rejected with typed errors.
- Cross-language test harness: decrypts real Laravel-generated vectors, and a PHP verifier
  decrypts Rust-generated vectors (both directions, all ciphers) in CI.
