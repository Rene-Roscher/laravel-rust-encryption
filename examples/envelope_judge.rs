//! Reads tokens as the implementations print them (see `examples/envelope.rs`) on stdin and prints,
//! as JSON on stdout, what this crate makes of each one. `e2e/compare.php` of the `laravel-interop`
//! package holds the result against what the tokens should give.

use std::io::Read;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use laravel_rust_encryption::{Cipher, Encrypter, OpenOptions};
use serde_json::{json, Value};

fn main() {
    let mut input = String::new();
    std::io::stdin()
        .read_to_string(&mut input)
        .expect("read stdin");
    let input: Value = serde_json::from_str(&input).expect("parse the tokens");
    let key = STANDARD
        .decode(input["key_b64"].as_str().unwrap())
        .expect("key");

    let judge = |cipher: &str, token: &str, scope: &str, leeway: u32, now: i64| -> Value {
        let cipher: Cipher = cipher.parse().unwrap();
        let enc = Encrypter::new(&key[..cipher.key_size()], cipher).unwrap();
        match enc.open_envelope_with(token, scope, OpenOptions::default().leeway(leeway).now(now)) {
            Ok(o) => json!({
                "verdict": "ok",
                "iat": o.issued_at,
                "nbf": o.not_before,
                "exp": o.expires_at,
                "data": o.data,
            }),
            Err(e) => json!({ "verdict": e.kind() }),
        }
    };

    let verdicts: Vec<Value> = input["verdicts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| {
            judge(
                v["cipher"].as_str().unwrap(),
                v["token"].as_str().unwrap(),
                v["scope"].as_str().unwrap(),
                v["leeway"].as_u64().unwrap().try_into().unwrap(),
                v["now"].as_i64().unwrap(),
            )
        })
        .collect();

    let sealed: Vec<Value> = input["sealed"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| {
            let case = &s["case"];
            // Open it once it is valid, so the check is about the fields and not the clock.
            let now =
                (case["now"].as_i64().unwrap() + 1).max(case["not_before"].as_i64().unwrap_or(0));
            judge(
                s["cipher"].as_str().unwrap(),
                s["token"].as_str().unwrap(),
                case["scope"].as_str().unwrap(),
                0,
                now,
            )
        })
        .collect();

    println!("{}", json!({ "verdicts": verdicts, "sealed": sealed }));
}
