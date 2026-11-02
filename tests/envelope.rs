use std::time::Duration;

use laravel_rust_encryption::{
    Cipher, Encrypter, EnvelopeError, Error, Expiry, OpenOptions, SealOptions,
};
use serde_json::json;

const NOW: i64 = 1_700_000_000;
const ALL: [Cipher; 4] = [
    Cipher::Aes128Cbc,
    Cipher::Aes256Cbc,
    Cipher::Aes128Gcm,
    Cipher::Aes256Gcm,
];

fn enc(cipher: Cipher) -> Encrypter {
    Encrypter::new(&vec![0x2b; cipher.key_size()], cipher).unwrap()
}

fn open_at(
    enc: &Encrypter,
    token: &str,
    scope: &str,
    now: i64,
    leeway: u32,
) -> Result<i64, String> {
    enc.open_envelope_with(token, scope, OpenOptions::default().now(now).leeway(leeway))
        .map(|o| o.data.as_i64().unwrap())
        .map_err(|e| e.kind().to_owned())
}

#[test]
fn round_trips_every_kind_of_data_for_every_cipher() {
    let values = [
        json!(null),
        json!(true),
        json!(0),
        json!(-7),
        json!(1.5),
        json!(""),
        json!("Grüße 世界 🚀 \"q\" \\ / <t> &"),
        json!([]),
        json!({}),
        json!([1, "two", [3], null]),
        json!({"a": {"b": null}}),
    ];
    for cipher in ALL {
        let enc = enc(cipher);
        for value in &values {
            let token = enc
                .seal_envelope("test", value, Expiry::In(Duration::from_secs(60)))
                .unwrap();
            let opened = enc.open_envelope(&token, "test").unwrap();
            assert_eq!(&opened.data, value, "{cipher}");
            assert_eq!(opened.scope, "test");
        }
    }
}

#[test]
fn works_with_serde_types() {
    #[derive(serde::Serialize)]
    struct Reset<'a> {
        user: u32,
        email: &'a str,
    }
    let enc = enc(Cipher::Aes256Gcm);
    let token = enc
        .seal_envelope(
            "password-reset",
            &Reset {
                user: 7,
                email: "a@b.c",
            },
            Expiry::Never,
        )
        .unwrap();
    let opened = enc.open_envelope(&token, "password-reset").unwrap();
    assert_eq!(opened.data, json!({"user": 7, "email": "a@b.c"}));

    #[derive(serde::Deserialize, PartialEq, Debug)]
    struct Back {
        user: u32,
    }
    assert_eq!(
        opened.clone().into_data::<Back>().unwrap(),
        Back { user: 7 }
    );
    assert!(opened.into_data::<Vec<u8>>().is_err());
}

#[test]
fn reports_the_timestamps() {
    let enc = enc(Cipher::Aes256Cbc);
    let sealed = |expiry, options: SealOptions| {
        let token = enc
            .seal_envelope_with("s", &1, expiry, options.now(NOW))
            .unwrap();
        enc.open_envelope_with(
            &token,
            "s",
            OpenOptions::default().now(NOW + 20).leeway(100),
        )
        .unwrap()
    };

    let o = sealed(
        Expiry::In(Duration::from_secs(3600)),
        SealOptions::default().not_before(NOW + 10),
    );
    assert_eq!(
        (o.issued_at, o.not_before, o.expires_at),
        (NOW, Some(NOW + 10), Some(NOW + 3600))
    );
    let o = sealed(Expiry::Never, SealOptions::default());
    assert_eq!((o.not_before, o.expires_at), (None, None));
    let o = sealed(Expiry::At(NOW + 99), SealOptions::default());
    assert_eq!(o.expires_at, Some(NOW + 99));
}

#[test]
fn checks_scope_expiry_and_not_before_against_the_clock() {
    let enc = enc(Cipher::Aes256Cbc);
    let token = enc
        .seal_envelope_with(
            "s",
            &1,
            Expiry::In(Duration::from_secs(100)),
            SealOptions::default().now(NOW).not_before(NOW + 50),
        )
        .unwrap();

    assert_eq!(
        open_at(&enc, &token, "s", NOW + 49, 0),
        Err("not_yet_valid".into())
    );
    assert_eq!(open_at(&enc, &token, "s", NOW + 50, 0), Ok(1));
    assert_eq!(open_at(&enc, &token, "s", NOW + 99, 0), Ok(1));
    assert_eq!(
        open_at(&enc, &token, "s", NOW + 100, 0),
        Err("expired".into())
    );
    assert_eq!(
        open_at(&enc, &token, "other", NOW + 60, 0),
        Err("scope_mismatch".into())
    );
    // The scope is judged before the time.
    assert_eq!(
        open_at(&enc, &token, "other", NOW + 500, 0),
        Err("scope_mismatch".into())
    );
}

#[test]
fn the_leeway_widens_both_time_checks() {
    let enc = enc(Cipher::Aes256Cbc);
    let token = enc
        .seal_envelope_with(
            "s",
            &1,
            Expiry::In(Duration::from_secs(100)),
            SealOptions::default().now(NOW).not_before(NOW + 50),
        )
        .unwrap();
    assert_eq!(open_at(&enc, &token, "s", NOW + 40, 10), Ok(1));
    assert_eq!(
        open_at(&enc, &token, "s", NOW + 39, 10),
        Err("not_yet_valid".into())
    );
    assert_eq!(open_at(&enc, &token, "s", NOW + 109, 10), Ok(1));
    assert_eq!(
        open_at(&enc, &token, "s", NOW + 110, 10),
        Err("expired".into())
    );
}

#[test]
fn uses_the_real_clock_by_default() {
    let enc = enc(Cipher::Aes256Cbc);
    let live = enc
        .seal_envelope("s", &"x", Expiry::In(Duration::from_secs(60)))
        .unwrap();
    assert_eq!(enc.open_envelope(&live, "s").unwrap().data, json!("x"));
    let dead = enc.seal_envelope("s", &"x", Expiry::At(1)).unwrap();
    assert_eq!(enc.open_envelope(&dead, "s").unwrap_err().kind(), "expired");
}

#[test]
fn rejects_arguments_that_cannot_make_a_good_envelope() {
    let enc = enc(Cipher::Aes256Cbc);
    for (scope, expiry) in [
        ("", Expiry::Never),
        ("s", Expiry::In(Duration::ZERO)),
        ("s", Expiry::In(Duration::from_millis(999))),
        ("s", Expiry::At(0)),
        ("s", Expiry::At(-5)),
    ] {
        let err = enc.seal_envelope(scope, &1, expiry).unwrap_err();
        assert!(
            matches!(err, EnvelopeError::InvalidArgument(_)),
            "{scope:?} {expiry:?}"
        );
        assert!(!err.to_string().is_empty());
    }
}

#[test]
fn previous_keys_apply() {
    let old = Encrypter::new(&[0x7a; 32], Cipher::Aes256Cbc).unwrap();
    let token = old
        .seal_envelope("s", &"legacy", Expiry::In(Duration::from_secs(60)))
        .unwrap();
    let rotated = Encrypter::new(&[0x2b; 32], Cipher::Aes256Cbc)
        .unwrap()
        .with_previous_keys([[0x7a; 32]])
        .unwrap();
    assert_eq!(
        rotated.open_envelope(&token, "s").unwrap().data,
        json!("legacy")
    );
    assert_eq!(
        enc(Cipher::Aes256Cbc)
            .open_envelope(&token, "s")
            .unwrap_err()
            .kind(),
        "decrypt_error"
    );
}

#[test]
fn a_payload_that_does_not_decrypt_is_a_decrypt_error() {
    let err = enc(Cipher::Aes256Cbc)
        .open_envelope("not a payload", "s")
        .unwrap_err();
    assert!(matches!(err, EnvelopeError::Decrypt(Error::InvalidPayload)));
    assert_eq!(err.kind(), "decrypt_error");
    assert_eq!(err.to_string(), "The payload is invalid.");
    assert!(std::error::Error::source(&err).is_some());
}

#[test]
fn errors_have_the_shared_names_and_messages() {
    for (err, kind) in [
        (EnvelopeError::Invalid, "invalid"),
        (EnvelopeError::UnsupportedVersion, "unsupported_version"),
        (EnvelopeError::ScopeMismatch, "scope_mismatch"),
        (EnvelopeError::NotYetValid, "not_yet_valid"),
        (EnvelopeError::Expired, "expired"),
        (EnvelopeError::InvalidArgument("x"), "invalid"),
    ] {
        assert_eq!(err.kind(), kind);
        assert!(!err.to_string().is_empty());
        assert!(std::error::Error::source(&err).is_none());
    }
}

#[test]
fn data_that_cannot_be_serialized_is_an_error() {
    use std::collections::HashMap;
    let enc = enc(Cipher::Aes256Cbc);
    // JSON object keys have to be strings.
    let bad: HashMap<(i32, i32), i32> = HashMap::from([((1, 2), 3)]);
    let err = enc.seal_envelope("s", &bad, Expiry::Never).unwrap_err();
    assert!(matches!(err, EnvelopeError::Serialize(_)));
    assert!(err.to_string().contains("cannot be serialized"));
    assert!(std::error::Error::source(&err).is_some());
}
