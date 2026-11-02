//! Prints, as JSON on stdout, Interop Envelope tokens made by this crate, for
//! `bin/verify-tokens.php` of the `laravel-interop` package to judge with the real Laravel
//! encrypter:
//!
//! - `verdicts`: every document of `fixtures/envelope-vectors.json`, encrypted here. PHP has to
//!   reach the verdict the vector names.
//! - `sealed`: tokens sealed by `seal_envelope_with` for each of the vector file's seal cases. PHP
//!   has to open them and read back what was sealed.

use std::time::Duration;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use laravel_rust_encryption::{Cipher, Encrypter, Expiry, SealOptions};
use serde_json::{json, Value};

fn main() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/fixtures/envelope-vectors.json"
    );
    let fixtures: Value =
        serde_json::from_str(&std::fs::read_to_string(path).expect("read the vectors"))
            .expect("parse the vectors");
    let key = STANDARD
        .decode(fixtures["key_b64"].as_str().unwrap())
        .unwrap();

    let encrypter = |cipher: Cipher| Encrypter::new(&key[..cipher.key_size()], cipher).unwrap();

    let mut verdicts = Vec::new();
    for v in fixtures["vectors"].as_array().unwrap() {
        let (Some(plaintext), "current") =
            (v["plaintext_b64"].as_str(), v["key"].as_str().unwrap())
        else {
            continue;
        };
        if v["expect"] == "decrypt_error" {
            continue;
        }
        let cipher: Cipher = v["cipher"].as_str().unwrap().parse().unwrap();
        let token = encrypter(cipher)
            .encrypt_bytes(&STANDARD.decode(plaintext).unwrap())
            .unwrap();
        let mut out = v.clone();
        out["token"] = Value::String(token);
        verdicts.push(out);
    }

    let mut sealed = Vec::new();
    for cipher in [Cipher::Aes256Cbc, Cipher::Aes128Gcm] {
        for case in fixtures["seal_cases"].as_array().unwrap() {
            let expiry = if let Some(seconds) = case["expiry"]["in"].as_u64() {
                Expiry::In(Duration::from_secs(seconds))
            } else if let Some(timestamp) = case["expiry"]["at"].as_i64() {
                Expiry::At(timestamp)
            } else {
                Expiry::Never
            };
            let mut options = SealOptions::default().now(case["now"].as_i64().unwrap());
            if let Some(not_before) = case["not_before"].as_i64() {
                options = options.not_before(not_before);
            }
            let token = encrypter(cipher)
                .seal_envelope_with(
                    case["scope"].as_str().unwrap(),
                    &case["data"],
                    expiry,
                    options,
                )
                .expect("seal");
            sealed.push(json!({
                "cipher": cipher.name(),
                "name": case["name"],
                "token": token,
                "case": case,
            }));
        }
    }

    println!(
        "{}",
        json!({ "key_b64": fixtures["key_b64"], "verdicts": verdicts, "sealed": sealed })
    );
}
