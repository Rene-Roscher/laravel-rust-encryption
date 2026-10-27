use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use base64::Engine as _;
use hmac::{Hmac, Mac};
use laravel_rust_encryption::{parse_key, Cipher, Encrypter, Error, Value};
use serde_json::{json, Value as Json};
use sha2::Sha256;

const ALL: [Cipher; 4] = [
    Cipher::Aes128Cbc,
    Cipher::Aes256Cbc,
    Cipher::Aes128Gcm,
    Cipher::Aes256Gcm,
];

fn key(cipher: Cipher, byte: u8) -> Vec<u8> {
    vec![byte; cipher.key_size()]
}

fn encrypter(cipher: Cipher) -> Encrypter {
    Encrypter::new(&key(cipher, 0x2b), cipher).unwrap()
}

fn is_cbc(cipher: Cipher) -> bool {
    matches!(cipher, Cipher::Aes128Cbc | Cipher::Aes256Cbc)
}

fn unwrap_payload(payload: &str) -> Json {
    serde_json::from_slice(&STANDARD.decode(payload).unwrap()).unwrap()
}

fn wrap_payload(json: &Json) -> String {
    STANDARD.encode(serde_json::to_vec(json).unwrap())
}

/// Re-encodes `payload` after applying `edit` to its JSON.
fn edit_payload(payload: &str, edit: impl FnOnce(&mut Json)) -> String {
    let mut json = unwrap_payload(payload);
    edit(&mut json);
    wrap_payload(&json)
}

/// Flips the first base64 character, changing the decoded bytes.
fn flip_first(s: &str) -> String {
    let mut chars: Vec<char> = s.chars().collect();
    chars[0] = if chars[0] == 'A' { 'B' } else { 'A' };
    chars.into_iter().collect()
}

#[test]
fn round_trips_strings_for_every_cipher() {
    let long = "line of text 0123456789\n".repeat(500);
    let inputs = [
        "",
        "x",
        "Hello, World!",
        "Grüße 世界 🚀 café",
        // Around the 16-byte block boundary, where padding changes.
        "0123456789abcde",
        "0123456789abcdef",
        "0123456789abcdef0",
        &long,
    ];
    for cipher in ALL {
        let enc = encrypter(cipher);
        for input in inputs {
            let payload = enc.encrypt_string(input).unwrap();
            assert_eq!(enc.decrypt_string(&payload).unwrap(), input, "{cipher}");
        }
    }
}

#[test]
fn round_trips_bytes_for_every_cipher() {
    let binary = [0x00, 0x01, 0x02, 0xff, 0xfe, 0x7f, 0x80];
    for cipher in ALL {
        let enc = encrypter(cipher);
        let payload = enc.encrypt_bytes(&binary).unwrap();
        assert_eq!(enc.decrypt_bytes(&payload).unwrap(), binary, "{cipher}");
        assert_eq!(enc.decrypt_string(&payload), Err(Error::InvalidUtf8));
    }
}

#[test]
fn round_trips_values_for_every_cipher() {
    let value = Value::map([
        ("user", Value::from("alice")),
        ("id", 7.into()),
        ("active", true.into()),
        ("score", 2.5.into()),
        ("tags", Value::list(["x", "y"])),
        ("meta", Value::Null),
    ]);
    for cipher in ALL {
        let enc = encrypter(cipher);
        let payload = enc.encrypt(&value).unwrap();
        assert_eq!(enc.decrypt(&payload).unwrap(), value, "{cipher}");
    }
}

#[test]
fn string_and_value_paths_are_distinct_like_in_laravel() {
    let enc = encrypter(Cipher::Aes256Cbc);

    // Crypt::encrypt serializes: decryptString shows the PHP serialization.
    let payload = enc.encrypt(&"hello".into()).unwrap();
    assert_eq!(enc.decrypt_string(&payload).unwrap(), r#"s:5:"hello";"#);

    // Crypt::encryptString does not: decrypt cannot unserialize it.
    let payload = enc.encrypt_string("hello").unwrap();
    assert_eq!(enc.decrypt(&payload), Err(Error::Unserialize));
}

#[test]
fn cbc_payload_has_laravels_layout() {
    for cipher in [Cipher::Aes128Cbc, Cipher::Aes256Cbc] {
        let key = key(cipher, 0x2b);
        let enc = Encrypter::new(&key, cipher).unwrap();
        let payload = enc.encrypt_string("hello").unwrap();

        // Field order matches Laravel's json_encode(['iv', 'value', 'mac', 'tag']).
        let json = String::from_utf8(STANDARD.decode(&payload).unwrap()).unwrap();
        let positions: Vec<_> = ["\"iv\"", "\"value\"", "\"mac\"", "\"tag\""]
            .iter()
            .map(|f| json.find(f).unwrap())
            .collect();
        assert!(positions.windows(2).all(|w| w[0] < w[1]), "{json}");

        let p = unwrap_payload(&payload);
        let (iv, value) = (p["iv"].as_str().unwrap(), p["value"].as_str().unwrap());
        assert_eq!(STANDARD.decode(iv).unwrap().len(), 16);
        assert_eq!(STANDARD.decode(value).unwrap().len(), 16); // "hello" + PKCS#7 padding
        assert_eq!(p["tag"], "");

        // mac = lower-case hex HMAC-SHA256(base64(iv) . base64(value), key)
        let mut mac = Hmac::<Sha256>::new_from_slice(&key).unwrap();
        mac.update(iv.as_bytes());
        mac.update(value.as_bytes());
        let expected: String = mac
            .finalize()
            .into_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(p["mac"], expected.as_str());
    }
}

#[test]
fn gcm_payload_has_laravels_layout() {
    for cipher in [Cipher::Aes128Gcm, Cipher::Aes256Gcm] {
        let enc = encrypter(cipher);
        let p = unwrap_payload(&enc.encrypt_string("hello").unwrap());
        assert_eq!(
            STANDARD.decode(p["iv"].as_str().unwrap()).unwrap().len(),
            12
        );
        // GCM is a stream mode: no padding.
        assert_eq!(
            STANDARD.decode(p["value"].as_str().unwrap()).unwrap().len(),
            5
        );
        assert_eq!(
            STANDARD.decode(p["tag"].as_str().unwrap()).unwrap().len(),
            16
        );
        assert_eq!(p["mac"], "");
    }
}

#[test]
fn every_encryption_uses_a_fresh_iv() {
    for cipher in ALL {
        let enc = encrypter(cipher);
        let a = enc.encrypt_string("same").unwrap();
        let b = enc.encrypt_string("same").unwrap();
        assert_ne!(a, b, "{cipher}");
        assert_ne!(
            unwrap_payload(&a)["iv"],
            unwrap_payload(&b)["iv"],
            "{cipher}"
        );
    }
}

#[test]
fn tampering_with_authenticated_fields_is_rejected() {
    for cipher in ALL {
        let enc = encrypter(cipher);
        let payload = enc.encrypt_string("a secret payload").unwrap();
        let fields: &[&str] = if is_cbc(cipher) {
            &["iv", "value", "mac"]
        } else {
            &["iv", "value", "tag"]
        };
        for field in fields {
            let tampered = edit_payload(&payload, |j| {
                let flipped = flip_first(j[*field].as_str().unwrap());
                j[*field] = json!(flipped);
            });
            assert!(
                enc.decrypt_string(&tampered).is_err(),
                "{cipher}: tampering with {field} was accepted"
            );
        }
    }
}

#[test]
fn tampered_cbc_value_or_mac_is_an_invalid_mac_and_never_reaches_decryption() {
    let enc = encrypter(Cipher::Aes256Cbc);
    let payload = enc.encrypt_string("a secret payload").unwrap();
    for field in ["value", "mac"] {
        let tampered = edit_payload(&payload, |j| {
            let flipped = flip_first(j[field].as_str().unwrap());
            j[field] = json!(flipped);
        });
        assert_eq!(enc.decrypt_string(&tampered), Err(Error::InvalidMac));
    }
    // hash_equals is case-sensitive: an upper-case MAC does not match.
    let upper = edit_payload(&payload, |j| {
        let mac = j["mac"].as_str().unwrap().to_uppercase();
        j["mac"] = json!(mac);
    });
    assert_eq!(enc.decrypt_string(&upper), Err(Error::InvalidMac));
}

#[test]
fn tampered_gcm_value_or_tag_fails_authentication() {
    let enc = encrypter(Cipher::Aes256Gcm);
    let payload = enc.encrypt_string("a secret payload").unwrap();
    for field in ["value", "tag"] {
        let tampered = edit_payload(&payload, |j| {
            let flipped = flip_first(j[field].as_str().unwrap());
            j[field] = json!(flipped);
        });
        assert_eq!(enc.decrypt_string(&tampered), Err(Error::Decrypt));
    }
}

#[test]
fn unauthenticated_fields_are_ignored_like_in_laravel() {
    // CBC: an empty tag (what Laravel writes) is fine, and unknown keys are ignored.
    let enc = encrypter(Cipher::Aes256Cbc);
    let payload = enc.encrypt_string("x").unwrap();
    let extra = edit_payload(&payload, |j| j["extra"] = json!("ignored"));
    assert_eq!(enc.decrypt_string(&extra).unwrap(), "x");
    let no_tag = edit_payload(&payload, |j| {
        j.as_object_mut().unwrap().remove("tag");
    });
    assert_eq!(enc.decrypt_string(&no_tag).unwrap(), "x");
    let null_tag = edit_payload(&payload, |j| j["tag"] = Json::Null);
    assert_eq!(enc.decrypt_string(&null_tag).unwrap(), "x");

    // PHP's empty("0") is true, so a "0" tag counts as no tag.
    let zero_tag = edit_payload(&payload, |j| j["tag"] = json!("0"));
    assert_eq!(enc.decrypt_string(&zero_tag).unwrap(), "x");

    // GCM: the mac field must be present but its content is not checked.
    let enc = encrypter(Cipher::Aes256Gcm);
    let payload = enc.encrypt_string("x").unwrap();
    let junk_mac = edit_payload(&payload, |j| j["mac"] = json!("whatever"));
    assert_eq!(enc.decrypt_string(&junk_mac).unwrap(), "x");
}

#[test]
fn the_gcm_value_is_decoded_leniently_like_openssl_decrypt_does() {
    // Laravel base64-decodes the value with base64_decode() in non-strict mode, which skips
    // characters outside the alphabet. The tag authenticates the decoded bytes, not the text.
    let enc = encrypter(Cipher::Aes256Gcm);
    let payload = enc.encrypt_string("hello").unwrap();
    let value = unwrap_payload(&payload)["value"]
        .as_str()
        .unwrap()
        .to_owned();
    let noisy = format!("{}\n{}*{}", &value[..2], &value[2..4], &value[4..]);
    let edited = edit_payload(&payload, |j| j["value"] = json!(noisy));
    assert_eq!(enc.decrypt_string(&edited).unwrap(), "hello");

    // ...but the decoded bytes themselves are authenticated.
    let edited = edit_payload(&payload, |j| j["value"] = json!(flip_first(&value)));
    assert_eq!(enc.decrypt_string(&edited), Err(Error::Decrypt));
}

#[test]
fn tag_rules_follow_laravel() {
    // A CBC payload must not carry a tag.
    let enc = encrypter(Cipher::Aes256Cbc);
    let payload = enc.encrypt_string("x").unwrap();
    let with_tag = edit_payload(&payload, |j| j["tag"] = json!(STANDARD.encode([0u8; 16])));
    assert_eq!(enc.decrypt_string(&with_tag), Err(Error::Decrypt));

    // A GCM payload needs a 16-byte tag.
    let enc = encrypter(Cipher::Aes256Gcm);
    let payload = enc.encrypt_string("x").unwrap();
    let tag = unwrap_payload(&payload)["tag"].as_str().unwrap().to_owned();
    let short = STANDARD.encode(&STANDARD.decode(&tag).unwrap()[..15]);
    for bad in [json!(""), json!(short), json!("!!!"), Json::Null] {
        let edited = edit_payload(&payload, |j| j["tag"] = bad.clone());
        assert_eq!(enc.decrypt_string(&edited), Err(Error::Decrypt), "{bad}");
    }
    let missing = edit_payload(&payload, |j| {
        j.as_object_mut().unwrap().remove("tag");
    });
    assert_eq!(enc.decrypt_string(&missing), Err(Error::Decrypt));
}

#[test]
fn wrong_key_is_rejected() {
    for cipher in ALL {
        let payload = encrypter(cipher).encrypt_string("secret").unwrap();
        let other = Encrypter::new(&key(cipher, 0x7a), cipher).unwrap();
        let err = other.decrypt_string(&payload).unwrap_err();
        let want = if is_cbc(cipher) {
            Error::InvalidMac
        } else {
            Error::Decrypt
        };
        assert_eq!(err, want, "{cipher}");
    }
}

#[test]
fn payload_for_another_cipher_is_rejected() {
    // The IV length differs between CBC (16) and GCM (12).
    let cbc = encrypter(Cipher::Aes256Cbc).encrypt_string("x").unwrap();
    let gcm = encrypter(Cipher::Aes256Gcm).encrypt_string("x").unwrap();
    assert_eq!(
        encrypter(Cipher::Aes256Gcm).decrypt_string(&cbc),
        Err(Error::InvalidPayload)
    );
    assert_eq!(
        encrypter(Cipher::Aes256Cbc).decrypt_string(&gcm),
        Err(Error::InvalidPayload)
    );
}

#[test]
fn malformed_payloads_are_invalid_payload_errors() {
    let enc = encrypter(Cipher::Aes256Cbc);
    let valid = enc.encrypt_string("x").unwrap();
    let wrap = |s: &str| STANDARD.encode(s);

    let cases = [
        String::new(),
        "not base64!!".into(),
        "Zm9vYmFy".into(), // base64 of "foobar": not JSON
        wrap("null"),
        wrap("[]"),
        wrap(r#""a string""#),
        wrap("{}"),
        wrap(r#"{"iv":"x"}"#),
        wrap(r#"{"iv":1,"value":"x","mac":"x"}"#),
        // Missing or non-string required fields.
        edit_payload(&valid, |j| {
            j.as_object_mut().unwrap().remove("mac");
        }),
        edit_payload(&valid, |j| j["mac"] = Json::Null),
        edit_payload(&valid, |j| j["value"] = json!(5)),
        edit_payload(&valid, |j| j["iv"] = json!(["a"])),
        edit_payload(&valid, |j| j["tag"] = json!(5)),
        // IV that is not base64 or has the wrong length.
        edit_payload(&valid, |j| j["iv"] = json!("***")),
        edit_payload(&valid, |j| j["iv"] = json!(STANDARD.encode([0u8; 15]))),
        edit_payload(&valid, |j| j["iv"] = json!(STANDARD.encode([0u8; 17]))),
        // Truncated payload.
        valid[..valid.len() / 2].to_owned(),
    ];
    for payload in &cases {
        assert_eq!(
            enc.decrypt_string(payload),
            Err(Error::InvalidPayload),
            "{payload:?}"
        );
        assert!(enc.decrypt(payload).is_err());
    }
}

#[test]
fn a_value_that_is_not_base64_fails_the_mac_check() {
    // The value is decoded leniently (see the GCM test), so for CBC it is the MAC over the text
    // that rejects it.
    let enc = encrypter(Cipher::Aes256Cbc);
    let payload = enc.encrypt_string("x").unwrap();
    let edited = edit_payload(&payload, |j| j["value"] = json!("***"));
    assert_eq!(enc.decrypt_string(&edited), Err(Error::InvalidMac));
}

#[test]
fn unusual_but_valid_encodings_are_accepted_like_php_does() {
    let enc = encrypter(Cipher::Aes256Cbc);
    let payload = enc.encrypt_string("x").unwrap();

    // Surrounding whitespace, e.g. from a file or header.
    assert_eq!(enc.decrypt_string(&format!(" {payload}\n")).unwrap(), "x");

    // base64_decode() does not need the padding.
    let unpadded = STANDARD_NO_PAD.encode(STANDARD.decode(&payload).unwrap());
    assert_eq!(enc.decrypt_string(&unpadded).unwrap(), "x");
}

#[test]
fn block_aligned_ciphertext_with_bad_padding_is_a_decrypt_error() {
    // A correctly authenticated payload whose plaintext has invalid PKCS#7 padding can only be
    // made with the key: build one by hand.
    let key = key(Cipher::Aes256Cbc, 0x2b);
    let enc = Encrypter::new(&key, Cipher::Aes256Cbc).unwrap();

    for value in [Vec::new(), vec![0u8; 15], vec![0u8; 16]] {
        let iv = STANDARD.encode([0u8; 16]);
        let value = STANDARD.encode(value);
        let mut mac = Hmac::<Sha256>::new_from_slice(&key).unwrap();
        mac.update(iv.as_bytes());
        mac.update(value.as_bytes());
        let mac: String = mac
            .finalize()
            .into_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let payload = wrap_payload(&json!({"iv": iv, "value": value, "mac": mac, "tag": ""}));
        assert_eq!(enc.decrypt_bytes(&payload), Err(Error::Decrypt));
    }
}

#[test]
fn key_sizes_are_enforced() {
    for cipher in ALL {
        let size = cipher.key_size();
        assert!(Encrypter::new(&vec![1; size], cipher).is_ok());
        for bad in [0, 1, size - 1, size + 1, 64] {
            assert_eq!(
                Encrypter::new(&vec![1; bad], cipher).unwrap_err(),
                Error::InvalidKeyLength {
                    expected: size,
                    actual: bad
                }
            );
        }
    }
    // A 16-byte key is not valid for a 256-bit cipher and vice versa.
    assert!(Encrypter::new(&[0; 16], Cipher::Aes256Cbc).is_err());
    assert!(Encrypter::new(&[0; 32], Cipher::Aes128Gcm).is_err());
}

#[test]
fn ciphers_parse_case_insensitively() {
    assert_eq!("aes-256-cbc".parse(), Ok(Cipher::Aes256Cbc));
    assert_eq!("AES-256-CBC".parse(), Ok(Cipher::Aes256Cbc));
    assert_eq!("Aes-128-Gcm".parse(), Ok(Cipher::Aes128Gcm));
    for bad in [
        "",
        "aes-256",
        "aes-192-cbc",
        "aes-256-ecb",
        "aes-256-ctr",
        "des",
    ] {
        assert_eq!(
            bad.parse::<Cipher>(),
            Err(Error::UnsupportedCipher),
            "{bad}"
        );
    }
    for cipher in ALL {
        assert_eq!(cipher.to_string().parse(), Ok(cipher));
    }
    assert_eq!(Cipher::default(), Cipher::Aes256Cbc);
}

#[test]
fn parses_app_key_forms() {
    let raw = [0x2bu8; 32];
    let b64 = STANDARD.encode(raw);

    assert_eq!(parse_key(&format!("base64:{b64}")).unwrap(), raw);
    assert_eq!(parse_key(&b64).unwrap(), raw);
    assert_eq!(parse_key(&STANDARD.encode([7u8; 16])).unwrap(), [7u8; 16]);

    // Anything else is the raw key.
    let raw_key = "this-is-a-32-byte-raw-secret-key";
    assert_eq!(parse_key(raw_key).unwrap(), raw_key.as_bytes());
    assert_eq!(parse_key("0123456789abcdef").unwrap(), b"0123456789abcdef");

    assert_eq!(parse_key(""), Err(Error::InvalidKey));
    assert_eq!(parse_key("base64:"), Ok(Vec::new()));

    // Laravel decodes the base64: form with PHP's lenient base64_decode: padding is optional and
    // characters outside the alphabet are skipped.
    let unpadded = STANDARD.encode([0xfbu8; 32]);
    assert!(unpadded.ends_with('='));
    assert_eq!(
        parse_key(&format!("base64:{}", unpadded.trim_end_matches('='))).unwrap(),
        [0xfbu8; 32]
    );
    assert_eq!(
        parse_key(&format!("base64:{}\n", unpadded)).unwrap(),
        [0xfbu8; 32]
    );
    // PHP: bin2hex(base64_decode("!!!not base64!!!")) === "9e8b5b6ac7ba"
    assert_eq!(
        parse_key("base64:!!!not base64!!!").unwrap(),
        [0x9e, 0x8b, 0x5b, 0x6a, 0xc7, 0xba]
    );
}

#[test]
fn from_app_key_matches_new() {
    let key = format!("base64:{}", STANDARD.encode([0x2bu8; 32]));
    let from_env = Encrypter::from_app_key(&key, Cipher::Aes256Cbc).unwrap();
    let raw = Encrypter::new(&[0x2b; 32], Cipher::Aes256Cbc).unwrap();
    assert_eq!(from_env.key(), raw.key());
    let payload = from_env.encrypt_string("x").unwrap();
    assert_eq!(raw.decrypt_string(&payload).unwrap(), "x");

    assert_eq!(
        Encrypter::from_app_key("base64:", Cipher::Aes256Cbc).unwrap_err(),
        Error::InvalidKeyLength {
            expected: 32,
            actual: 0
        }
    );
    assert_eq!(
        Encrypter::from_app_key("", Cipher::Aes256Cbc).unwrap_err(),
        Error::InvalidKey
    );
    // A malformed value decodes to the wrong length, as in Laravel.
    assert_eq!(
        Encrypter::from_app_key("base64:@@@@", Cipher::Aes256Cbc).unwrap_err(),
        Error::InvalidKeyLength {
            expected: 32,
            actual: 0
        }
    );
}

#[test]
fn generated_keys_fit_their_cipher() {
    for cipher in ALL {
        let a = Encrypter::generate_key(cipher).unwrap();
        let b = Encrypter::generate_key(cipher).unwrap();
        assert_eq!(a.len(), cipher.key_size());
        assert_ne!(a, b);
        let enc = Encrypter::new(&a, cipher).unwrap();
        assert_eq!(
            enc.decrypt_string(&enc.encrypt_string("x").unwrap())
                .unwrap(),
            "x"
        );
    }
}

#[test]
fn previous_keys_decrypt_old_payloads_but_new_ones_use_the_current_key() {
    for cipher in ALL {
        let old = Encrypter::new(&key(cipher, 0x01), cipher).unwrap();
        let older = Encrypter::new(&key(cipher, 0x02), cipher).unwrap();
        let current_only = Encrypter::new(&key(cipher, 0x03), cipher).unwrap();
        let rotated = current_only
            .clone()
            .with_previous_keys([key(cipher, 0x01), key(cipher, 0x02)])
            .unwrap();

        for legacy in [&old, &older] {
            let payload = legacy.encrypt_string("legacy").unwrap();
            assert!(current_only.decrypt_string(&payload).is_err());
            assert_eq!(rotated.decrypt_string(&payload).unwrap(), "legacy");
        }

        // New payloads use the current key only.
        let fresh = rotated.encrypt_string("fresh").unwrap();
        assert_eq!(current_only.decrypt_string(&fresh).unwrap(), "fresh");
        assert!(old.decrypt_string(&fresh).is_err());

        // An unrelated key is still rejected.
        let stranger = Encrypter::new(&key(cipher, 0x09), cipher)
            .unwrap()
            .encrypt_string("x")
            .unwrap();
        assert!(rotated.decrypt_string(&stranger).is_err());

        // Tampering is still caught with previous keys configured.
        let payload = old.encrypt_string("legacy").unwrap();
        let tampered = edit_payload(&payload, |j| {
            let flipped = flip_first(j["value"].as_str().unwrap());
            j["value"] = json!(flipped);
        });
        assert!(rotated.decrypt_string(&tampered).is_err());
    }
}

#[test]
fn previous_keys_must_fit_the_cipher() {
    let enc = encrypter(Cipher::Aes256Cbc);
    assert_eq!(
        enc.with_previous_keys([vec![0u8; 16]]).unwrap_err(),
        Error::InvalidKeyLength {
            expected: 32,
            actual: 16
        }
    );
}

#[test]
fn appears_encrypted_inspects_the_payload_shape() {
    for cipher in ALL {
        let payload = encrypter(cipher).encrypt_string("x").unwrap();
        assert!(Encrypter::appears_encrypted(&payload), "{cipher}");
    }
    let valid = encrypter(Cipher::Aes256Cbc).encrypt_string("x").unwrap();
    let missing_mac = edit_payload(&valid, |j| {
        j.as_object_mut().unwrap().remove("mac");
    });
    for not in ["", "plain text", "e30=", "bnVsbA==", &missing_mac] {
        assert!(!Encrypter::appears_encrypted(not), "{not:?}");
    }
}

#[test]
fn debug_output_does_not_leak_keys() {
    let enc = Encrypter::new(b"0123456789abcdef0123456789abcdef", Cipher::Aes256Cbc)
        .unwrap()
        .with_previous_keys([b"fedcba9876543210fedcba9876543210"])
        .unwrap();
    let shown = format!("{enc:?}");
    assert!(!shown.contains("0123456789abcdef"));
    assert!(!shown.contains("fedcba98"));
    assert!(shown.contains("Aes256Cbc"));
}

#[test]
fn encrypter_can_be_shared_between_threads() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Encrypter>();

    let enc = std::sync::Arc::new(encrypter(Cipher::Aes256Gcm));
    let handles: Vec<_> = (0..4)
        .map(|i| {
            let enc = enc.clone();
            std::thread::spawn(move || {
                let text = format!("message {i}");
                let payload = enc.encrypt_string(&text).unwrap();
                assert_eq!(enc.decrypt_string(&payload).unwrap(), text);
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
}

/// The decrypter must reject, never panic on, arbitrary input: random garbage, and valid
/// payloads with bytes flipped, inserted or cut.
#[test]
fn arbitrary_input_never_panics() {
    let mut state = 0x2545_F491_4F6C_DD1D_u64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };

    for cipher in ALL {
        let enc = encrypter(cipher);
        let valid = enc.encrypt(&Value::list(["a", "b"])).unwrap().into_bytes();

        for _ in 0..3000 {
            let mut bytes = valid.clone();
            for _ in 0..(next() % 4) {
                let at = (next() as usize) % bytes.len();
                match next() % 3 {
                    0 => bytes[at] = (next() & 0x7f) as u8,
                    1 => bytes.insert(at, b'A' + (next() % 26) as u8),
                    _ => bytes.truncate(at.max(1)),
                }
            }
            let text = String::from_utf8_lossy(&bytes);
            let _ = enc.decrypt(&text);
            let _ = enc.decrypt_string(&text);
        }

        for _ in 0..1000 {
            let len = (next() % 200) as usize;
            let garbage: String = (0..len).map(|_| (next() & 0x7f) as u8 as char).collect();
            let _ = enc.decrypt(&garbage);
            let _ = enc.decrypt(&STANDARD.encode(&garbage));
        }
    }
}

#[test]
fn decryption_errors_use_laravels_messages() {
    assert_eq!(Error::InvalidPayload.to_string(), "The payload is invalid.");
    assert_eq!(Error::InvalidMac.to_string(), "The MAC is invalid.");
    assert_eq!(Error::Decrypt.to_string(), "Could not decrypt the data.");
    assert_eq!(Error::Encrypt.to_string(), "Could not encrypt the data.");

    // Every variant has a message, and the error can be used as a `dyn Error`.
    let all = [
        Error::UnsupportedCipher,
        Error::InvalidKey,
        Error::InvalidKeyLength {
            expected: 32,
            actual: 5,
        },
        Error::Unserialize,
        Error::Serialize,
        Error::InvalidCookie,
        Error::InvalidUtf8,
    ];
    for e in all {
        assert!(!e.to_string().is_empty());
        let _: &dyn std::error::Error = &e;
    }
    assert!(Error::InvalidKeyLength {
        expected: 32,
        actual: 5
    }
    .to_string()
    .contains("expected 32 bytes, got 5"));
}

#[test]
fn value_helpers() {
    let value = Value::map([
        ("name", Value::from("alice")),
        ("age", 30.into()),
        ("ratio", 0.5.into()),
        ("admin", false.into()),
        ("nick", Option::<&str>::None.into()),
        ("langs", vec!["rust", "php"].into()),
    ]);
    assert_eq!(value.get("name").and_then(Value::as_str), Some("alice"));
    assert_eq!(value.get("age").and_then(Value::as_i64), Some(30));
    assert_eq!(value.get("ratio").and_then(Value::as_f64), Some(0.5));
    assert_eq!(value.get("admin").and_then(Value::as_bool), Some(false));
    assert!(value.get("nick").unwrap().is_null());
    assert_eq!(
        value
            .get("langs")
            .and_then(Value::as_list)
            .map(<[Value]>::len),
        Some(2)
    );
    assert!(value.get("missing").is_none());

    // Accessors do not coerce.
    assert_eq!(value.get("age").and_then(Value::as_str), None);
    assert_eq!(value.get("name").and_then(Value::as_i64), None);
    assert_eq!(Value::Null.get("x"), None);
    assert_eq!(Value::Int(1).as_list(), None);

    assert_eq!(Value::from(1u8), Value::Int(1));
    assert_eq!(Value::from(-1i16), Value::Int(-1));
    assert_eq!(Value::from(1.5f32), Value::Float(1.5));
    assert_eq!(Value::from(Some(5)), Value::Int(5));
    assert_eq!(Value::from(String::from("s")), Value::String("s".into()));
}
