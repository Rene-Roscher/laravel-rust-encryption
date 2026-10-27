//! Emits Rust-encrypted Laravel payloads as JSON on stdout. CI pipes this into
//! `scripts/verify_rust_vectors.php`, which decrypts each with the real Laravel encrypter and
//! asserts equality: the Rust -> Laravel direction (the PHP-generated fixtures cover
//! Laravel -> Rust).
//!
//! "string" vectors use `encrypt_bytes` / `decryptString`; "serialized" vectors use
//! `encrypt` / `decrypt` and build the values named in `scripts/cases.php`. The app-layer
//! vectors cover random keys, cookies, Eloquent encrypted casts and encrypted sessions.

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

    app_layer_vectors(&mut vectors);

    println!("{}", json!({ "key_b64": base64(&KEY), "vectors": vectors }));
}

const ALL_CIPHERS: [Cipher; 4] = [
    Cipher::Aes128Cbc,
    Cipher::Aes256Cbc,
    Cipher::Aes128Gcm,
    Cipher::Aes256Gcm,
];

/// Random keys, cookies, Eloquent encrypted casts and encrypted sessions.
fn app_layer_vectors(vectors: &mut Vec<serde_json::Value>) {
    for cipher in ALL_CIPHERS {
        let name = |what: &str| format!("{cipher}/{what}");

        // Random keys: every byte value can appear in a key.
        for i in 0..6 {
            let key = Encrypter::generate_key(cipher).expect("random key");
            let enc = Encrypter::new(&key, cipher).expect("valid key");
            for (n, text) in ["Hello, World!", "", "Grüße 世界 🚀 café"]
                .iter()
                .enumerate()
            {
                vectors.push(json!({
                    "kind": "random_key",
                    "name": name(&format!("key{i}/{n}")),
                    "cipher": cipher.name(),
                    "key_b64": base64(&key),
                    "plaintext_b64": base64(text.as_bytes()),
                    "payload": enc.encrypt_string(text).expect("encrypt"),
                }));
            }
        }

        let enc = Encrypter::new(&KEY[..cipher.key_size()], cipher).expect("valid key");

        // Cookies, as EncryptCookies expects them.
        for (cookie, value) in [
            (
                "laravel_session",
                "0123456789abcdef0123456789abcdef01234567",
            ),
            ("XSRF-TOKEN", ""),
            ("a b", "with|pipe|chars"),
            ("küche", "Grüße 世界"),
        ] {
            vectors.push(json!({
                "kind": "cookie",
                "name": name(&format!("cookie/{cookie}")),
                "cipher": cipher.name(),
                "cookie_name": cookie,
                "value_b64": base64(value.as_bytes()),
                "payload": enc.encrypt_cookie(cookie, value).expect("encrypt"),
            }));
        }

        // Eloquent casts: encrypted values are Crypt::encryptString() of the value or its JSON.
        for (attribute, plain) in [
            ("plain", "hello wörld"),
            ("list", r#"{"x":1,"y":[1,2],"z":"ü"}"#),
            ("object", r#"{"k":"v","n":3}"#),
            ("collection", r#"[1,"two",3.5]"#),
        ] {
            vectors.push(json!({
                "kind": "cast",
                "name": name(&format!("cast/{attribute}")),
                "cipher": cipher.name(),
                "attribute": attribute,
                "plaintext_b64": base64(plain.as_bytes()),
                "payload": enc.encrypt_string(plain).expect("encrypt"),
            }));
        }

        // Encrypted sessions: Crypt::encrypt() of the serialized attributes.
        let attributes = Value::map([
            ("user_id", Value::from(7)),
            ("cart", Value::map([("apple", 2), ("pear", 1)])),
            ("name", Value::from("Grüße")),
        ]);
        let php = String::from_utf8(attributes.to_php_serialized().expect("serialize"))
            .expect("ASCII and UTF-8 only");
        let json_attributes = r#"{"user_id":7,"cart":{"apple":2,"pear":1},"name":"Grüße"}"#;
        for (serialization, inner) in [("php", php.as_str()), ("json", json_attributes)] {
            vectors.push(json!({
                "kind": "session",
                "name": name(&format!("session/{serialization}")),
                "cipher": cipher.name(),
                "serialization": serialization,
                "payload": enc.encrypt(&Value::String(inner.to_owned())).expect("encrypt"),
            }));
        }
    }
}

fn base64(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}
