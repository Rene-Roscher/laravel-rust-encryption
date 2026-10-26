//! Emits Rust-encrypted Laravel payloads as JSON on stdout. CI pipes this into
//! `scripts/verify_rust_vectors.php`, which decrypts each with the real Laravel encrypter and
//! asserts equality: the Rust -> Laravel direction (the PHP-generated fixtures cover
//! Laravel -> Rust).
//!
//! "string" vectors use `encrypt_bytes` / `decryptString`; "serialized" vectors use
//! `encrypt` / `decrypt` and build the values named in `scripts/cases.php`.

use laravel_rust_encryption::{Cipher, Encrypter, Value};
use serde_json::json;

const KEY: [u8; 32] = [0x2b; 32];

fn strings() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("simple", b"Hello from Rust".to_vec()),
        ("empty", Vec::new()),
        ("unicode", "Grüße 世界 🚀 café".as_bytes().to_vec()),
        ("json", br#"{"user":"alice","id":7,"active":true}"#.to_vec()),
        ("multiline", b"first line\nsecond line\n".to_vec()),
        ("binary", vec![0x00, 0x01, 0xff, 0xfe, 0x80, 0x7f]),
        ("block_aligned", vec![b'a'; 32]),
        (
            "long",
            "The quick brown fox 0123456789 ".repeat(50).into_bytes(),
        ),
    ]
}

fn cases() -> Vec<(&'static str, Value)> {
    vec![
        ("null", Value::Null),
        ("true", true.into()),
        ("false", false.into()),
        ("int_zero", 0.into()),
        ("int_negative", (-42).into()),
        ("int_max", i64::MAX.into()),
        ("int_min", i64::MIN.into()),
        ("float", 2.5.into()),
        ("float_whole", 2.0.into()),
        ("float_tenth", 0.1.into()),
        ("float_large", 1.0e25.into()),
        ("float_small", 1.5e-7.into()),
        ("float_negative_zero", (-0.0).into()),
        ("float_pi", std::f64::consts::PI.into()),
        ("float_max", f64::MAX.into()),
        ("float_min_subnormal", 4.9e-324.into()),
        ("float_inf", f64::INFINITY.into()),
        ("float_negative_inf", f64::NEG_INFINITY.into()),
        ("float_nan", f64::NAN.into()),
        ("string_empty", "".into()),
        ("string_unicode", "Grüße 世界 🚀 café".into()),
        ("string_quotes", r#"say "hi"; s:3:"x";"#.into()),
        ("string_binary", Value::Bytes(vec![0x00, 0xff, 0xfe, 0x80])),
        (
            "list",
            Value::list([
                Value::Int(1),
                "two".into(),
                true.into(),
                Value::Null,
                Value::list([3, 4]),
            ]),
        ),
        ("empty_array", Value::List(vec![])),
        (
            "assoc",
            Value::map([
                ("user", Value::from("alice")),
                ("id", 7.into()),
                ("active", true.into()),
                ("score", 2.5.into()),
                ("tags", Value::list(["x", "y"])),
                ("meta", Value::Null),
            ]),
        ),
        (
            "mixed_keys",
            Value::Map(vec![
                (5.into(), "a".into()),
                ("x".into(), "b".into()),
                (7.into(), Value::map([("nested", Value::list([1, 2]))])),
            ]),
        ),
        (
            "non_sequential_list",
            Value::Map(vec![(1.into(), "a".into()), (0.into(), "b".into())]),
        ),
        (
            "nested",
            Value::map([(
                "l1",
                Value::map([(
                    "l2",
                    Value::map([(
                        "l3",
                        Value::List(vec!["deep".into(), 1.5.into(), false.into()]),
                    )]),
                )]),
            )]),
        ),
    ]
}

fn main() {
    let mut vectors = Vec::new();
    for cipher in [
        Cipher::Aes128Cbc,
        Cipher::Aes256Cbc,
        Cipher::Aes128Gcm,
        Cipher::Aes256Gcm,
    ] {
        let enc = Encrypter::new(&KEY[..cipher.key_size()], cipher).expect("valid key");

        for (name, plaintext) in strings() {
            vectors.push(json!({
                "kind": "string",
                "name": format!("{cipher}/{name}"),
                "cipher": cipher.name(),
                "plaintext_b64": base64(&plaintext),
                "payload": enc.encrypt_bytes(&plaintext).expect("encrypt"),
            }));
        }
        for (name, value) in cases() {
            vectors.push(json!({
                "kind": "serialized",
                "name": format!("{cipher}/{name}"),
                "case": name,
                "cipher": cipher.name(),
                "payload": enc.encrypt(&value).expect("encrypt"),
            }));
        }
    }

    println!("{}", json!({ "key_b64": base64(&KEY), "vectors": vectors }));
}

fn base64(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}
