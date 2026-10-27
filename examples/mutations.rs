//! Emits valid and mutated payloads together with this crate's verdict on each, as JSON on
//! stdout. CI pipes this into `scripts/verify_mutations.php`, which asks the real Laravel
//! encrypter about the same payloads: both must accept and reject exactly the same ones, and
//! return the same plaintext for the accepted ones. Laravel versions that have
//! `Encrypter::appearsEncrypted()` are also asked whether each payload looks encrypted.

use std::io::Write as _;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use laravel_rust_encryption::{Cipher, Encrypter};
use serde_json::{json, Value};

/// Field values that exercise PHP's loose typing: null, empty, "0", numbers, arrays, short
/// or invalid base64.
fn odd_values() -> Vec<Value> {
    vec![
        json!(null),
        json!(""),
        json!("0"),
        json!(5),
        json!(true),
        json!([]),
        json!("AAAA"),
        json!("***"),
        json!("AAAAAAAAAAAAAAAAAAAAAA=="),
    ]
}

fn main() {
    let mut state = 0x1234_5678_9abc_def1_u64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let encode = |j: &Value| STANDARD.encode(serde_json::to_vec(j).expect("serialize"));

    let mut cases = Vec::new();
    for cipher in [
        Cipher::Aes128Cbc,
        Cipher::Aes256Cbc,
        Cipher::Aes128Gcm,
        Cipher::Aes256Gcm,
    ] {
        let enc = Encrypter::new(&vec![0x2b; cipher.key_size()], cipher).expect("valid key");

        for text in ["", "hello", "0123456789abcdef"] {
            let valid = enc.encrypt_string(text).expect("encrypt");
            let base: Value =
                serde_json::from_slice(&STANDARD.decode(&valid).expect("base64")).expect("json");

            let mut payloads = vec![
                valid.clone(),
                format!(" {valid}\n"),
                valid.trim_end_matches('=').to_owned(),
            ];

            // Field-level edits: odd values, removal, upper case, an extra character.
            for field in ["iv", "value", "mac", "tag"] {
                for odd in odd_values() {
                    let mut j = base.clone();
                    j[field] = odd;
                    payloads.push(encode(&j));
                }
                let mut j = base.clone();
                j.as_object_mut().expect("object").remove(field);
                payloads.push(encode(&j));

                let text = base[field].as_str().expect("string").to_owned();
                let mut j = base.clone();
                j[field] = json!(text.to_uppercase());
                payloads.push(encode(&j));
                let mut j = base.clone();
                j[field] = json!(format!("{text}A"));
                payloads.push(encode(&j));
            }

            // Byte-level edits of the outer base64 text.
            for _ in 0..600 {
                let mut b = valid.clone().into_bytes();
                let at = next() as usize % b.len();
                match next() % 5 {
                    0 => b[at] = b"ABCxyz09+/=!\n "[next() as usize % 14],
                    1 => {
                        b.remove(at);
                    }
                    2 => b.truncate(at),
                    3 => b.insert(at, b" \n=*"[next() as usize % 4]),
                    _ => {
                        let other = next() as usize % b.len();
                        b.swap(at, other);
                    }
                }
                payloads.push(String::from_utf8_lossy(&b).into_owned());
            }

            for payload in payloads {
                let plain = enc.decrypt_string(&payload).ok();
                let appears = Encrypter::appears_encrypted(&payload);
                cases.push(json!({ "cipher": cipher.name(), "payload": payload, "plain": plain, "appears": appears }));
            }
        }
    }

    // A closed pipe (PHP exited early) is not an error worth a panic.
    let _ = writeln!(
        std::io::stdout(),
        "{}",
        json!({ "key_b64": STANDARD.encode([0x2b; 32]), "cases": cases })
    );
}
