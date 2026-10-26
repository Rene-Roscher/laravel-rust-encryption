//! PHP `serialize()` / `unserialize()` for the value set Laravel's `Crypt::encrypt` /
//! `Crypt::decrypt` round-trips.

use std::fmt::Write as _;

use crate::error::{Error, Result};

/// Maximum nesting depth accepted when decoding.
const MAX_DEPTH: usize = 128;

/// A PHP value, as produced by `unserialize()` or accepted by `serialize()`.
///
/// PHP arrays are ordered maps with `int` or `string` keys. An array whose keys are exactly
/// `0..n` in order decodes to [`Value::List`]; any other array decodes to [`Value::Map`],
/// which keeps PHP's key order.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// PHP `null`.
    Null,
    /// PHP `bool`.
    Bool(bool),
    /// PHP `int` (64-bit).
    Int(i64),
    /// PHP `float`.
    Float(f64),
    /// PHP `string` holding valid UTF-8.
    String(String),
    /// PHP `string` that is not valid UTF-8. Decoding yields this variant only for such
    /// strings; both string variants serialize to a PHP `string`.
    Bytes(Vec<u8>),
    /// PHP `array` with the keys `0..n`.
    List(Vec<Value>),
    /// PHP `array` with any other keys, in PHP order.
    Map(Vec<(Key, Value)>),
    /// A PHP object. **Decode-only**: the class is never instantiated or looked up, so
    /// decrypting untrusted payloads cannot trigger unserialize gadget chains, and the
    /// value cannot be serialized again ([`Error::Serialize`]). Property names keep PHP's
    /// visibility mangling (`"\0*\0name"` for protected, `"\0Class\0name"` for private).
    Object {
        /// Class name.
        class: String,
        /// Properties in PHP order.
        properties: Vec<(Key, Value)>,
    },
}

/// A PHP array key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Key {
    /// Integer key.
    Int(i64),
    /// String key.
    String(String),
}

impl Value {
    /// Builds a [`Value::List`] from an iterator.
    pub fn list<I, V>(items: I) -> Self
    where
        I: IntoIterator<Item = V>,
        V: Into<Value>,
    {
        Value::List(items.into_iter().map(Into::into).collect())
    }

    /// Builds a [`Value::Map`] from key/value pairs, keeping their order.
    pub fn map<I, K, V>(entries: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<Key>,
        V: Into<Value>,
    {
        Value::Map(
            entries
                .into_iter()
                .map(|(k, v)| (k.into(), v.into()))
                .collect(),
        )
    }

    /// Returns `true` for [`Value::Null`].
    pub fn is_null(&self) -> bool {
        matches!(self, Value::Null)
    }

    /// Returns the value of a [`Value::Bool`].
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// Returns the value of a [`Value::Int`].
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Value::Int(i) => Some(*i),
            _ => None,
        }
    }

    /// Returns the value of a [`Value::Float`].
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Value::Float(f) => Some(*f),
            _ => None,
        }
    }

    /// Returns the text of a [`Value::String`].
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::String(s) => Some(s),
            _ => None,
        }
    }

    /// Returns the items of a [`Value::List`].
    pub fn as_list(&self) -> Option<&[Value]> {
        match self {
            Value::List(items) => Some(items),
            _ => None,
        }
    }

    /// Looks up a string key in a [`Value::Map`] or the properties of a [`Value::Object`].
    pub fn get(&self, key: &str) -> Option<&Value> {
        let entries = match self {
            Value::Map(entries) => entries,
            Value::Object { properties, .. } => properties,
            _ => return None,
        };
        entries
            .iter()
            .find(|(k, _)| matches!(k, Key::String(s) if s == key))
            .map(|(_, v)| v)
    }
}

impl From<&str> for Key {
    fn from(s: &str) -> Self {
        Key::String(s.to_owned())
    }
}

impl From<String> for Key {
    fn from(s: String) -> Self {
        Key::String(s)
    }
}

impl From<i64> for Key {
    fn from(i: i64) -> Self {
        Key::Int(i)
    }
}

impl From<i32> for Key {
    fn from(i: i32) -> Self {
        Key::Int(i64::from(i))
    }
}

impl From<bool> for Value {
    fn from(b: bool) -> Self {
        Value::Bool(b)
    }
}

macro_rules! value_from_int {
    ($($t:ty),*) => {$(
        impl From<$t> for Value {
            fn from(i: $t) -> Self {
                Value::Int(i64::from(i))
            }
        }
    )*};
}
value_from_int!(i8, i16, i32, i64, u8, u16, u32);

impl From<f32> for Value {
    fn from(f: f32) -> Self {
        Value::Float(f64::from(f))
    }
}

impl From<f64> for Value {
    fn from(f: f64) -> Self {
        Value::Float(f)
    }
}

impl From<&str> for Value {
    fn from(s: &str) -> Self {
        Value::String(s.to_owned())
    }
}

impl From<String> for Value {
    fn from(s: String) -> Self {
        Value::String(s)
    }
}

impl<T: Into<Value>> From<Vec<T>> for Value {
    fn from(items: Vec<T>) -> Self {
        Value::list(items)
    }
}

impl<T: Into<Value>> From<Option<T>> for Value {
    fn from(v: Option<T>) -> Self {
        v.map_or(Value::Null, Into::into)
    }
}

/// PHP's `serialize()`.
pub(crate) fn serialize(value: &Value) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    encode(&mut out, value)?;
    Ok(out)
}

fn encode(out: &mut Vec<u8>, value: &Value) -> Result<()> {
    match value {
        Value::Null => out.extend_from_slice(b"N;"),
        Value::Bool(b) => out.extend_from_slice(if *b { b"b:1;" } else { b"b:0;" }),
        Value::Int(i) => push_fmt(out, format_args!("i:{i};")),
        Value::Float(f) => push_fmt(out, format_args!("d:{};", format_float(*f))),
        Value::String(s) => encode_string(out, s.as_bytes()),
        Value::Bytes(b) => encode_string(out, b),
        Value::List(items) => {
            push_fmt(out, format_args!("a:{}:{{", items.len()));
            for (i, item) in items.iter().enumerate() {
                push_fmt(out, format_args!("i:{i};"));
                encode(out, item)?;
            }
            out.push(b'}');
        }
        Value::Map(entries) => {
            push_fmt(out, format_args!("a:{}:{{", entries.len()));
            for (key, item) in entries {
                match key {
                    Key::Int(i) => push_fmt(out, format_args!("i:{i};")),
                    Key::String(s) => encode_string(out, s.as_bytes()),
                }
                encode(out, item)?;
            }
            out.push(b'}');
        }
        Value::Object { .. } => return Err(Error::Serialize),
    }
    Ok(())
}

fn push_fmt(out: &mut Vec<u8>, args: std::fmt::Arguments<'_>) {
    let mut s = String::new();
    // Writing to a String cannot fail.
    let _ = s.write_fmt(args);
    out.extend_from_slice(s.as_bytes());
}

fn encode_string(out: &mut Vec<u8>, bytes: &[u8]) {
    push_fmt(out, format_args!("s:{}:\"", bytes.len()));
    out.extend_from_slice(bytes);
    out.extend_from_slice(b"\";");
}

/// Formats a float the way PHP's `serialize()` does (`serialize_precision = -1`): the
/// shortest digits that round-trip, in fixed notation unless the decimal exponent is below
/// -4 or above 17, e.g. `2`, `0.1`, `1.0E+25`, `1.5E-7`.
fn format_float(f: f64) -> String {
    if f.is_nan() {
        return "NAN".into();
    }
    if f.is_infinite() {
        return if f > 0.0 { "INF" } else { "-INF" }.into();
    }
    if f == 0.0 {
        return if f.is_sign_negative() { "-0" } else { "0" }.into();
    }

    // `{:e}` yields the shortest round-trip digits: "d.ddde<exp>".
    let sci = format!("{:e}", f.abs());
    let (mantissa, exp) = sci.split_once('e').unwrap_or((&sci, "0"));
    let digits: String = mantissa.chars().filter(|c| *c != '.').collect();
    let exp: i32 = exp.parse().unwrap_or(0);
    // Position of the decimal point relative to the first digit (PHP's `decpt`).
    let decpt = exp + 1;

    let mut out = String::new();
    if f < 0.0 {
        out.push('-');
    }

    let (first, rest) = digits.split_at(1);
    if !(-3..=17).contains(&decpt) {
        out.push_str(first);
        out.push('.');
        out.push_str(if rest.is_empty() { "0" } else { rest });
        let _ = write!(out, "E{}{}", if exp < 0 { '-' } else { '+' }, exp.abs());
    } else if decpt <= 0 {
        out.push_str("0.");
        out.push_str(&"0".repeat((-decpt) as usize));
        out.push_str(&digits);
    } else {
        let int_len = decpt as usize;
        if digits.len() <= int_len {
            out.push_str(&digits);
            out.push_str(&"0".repeat(int_len - digits.len()));
        } else {
            out.push_str(&digits[..int_len]);
            out.push('.');
            out.push_str(&digits[int_len..]);
        }
    }
    out
}

/// PHP's `unserialize()`, restricted to the types in [`Value`]. Trailing data is an error.
pub(crate) fn unserialize(data: &[u8]) -> Result<Value> {
    let mut d = Decoder { data, pos: 0 };
    let value = d.value(0)?;
    if d.pos != data.len() {
        return Err(Error::Unserialize);
    }
    Ok(value)
}

struct Decoder<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Decoder<'a> {
    fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    fn expect(&mut self, lit: &[u8]) -> Result<()> {
        if self.data[self.pos..].starts_with(lit) {
            self.pos += lit.len();
            Ok(())
        } else {
            Err(Error::Unserialize)
        }
    }

    /// Returns the bytes up to `sep` and moves past it.
    fn until(&mut self, sep: u8) -> Result<&'a [u8]> {
        let rest = &self.data[self.pos..];
        let n = rest
            .iter()
            .position(|&b| b == sep)
            .ok_or(Error::Unserialize)?;
        self.pos += n + 1;
        Ok(&rest[..n])
    }

    fn int(&mut self, sep: u8) -> Result<i64> {
        let raw = self.until(sep)?;
        std::str::from_utf8(raw)
            .ok()
            .and_then(|s| s.parse::<i64>().ok())
            .ok_or(Error::Unserialize)
    }

    fn len(&mut self, sep: u8) -> Result<usize> {
        usize::try_from(self.int(sep)?).map_err(|_| Error::Unserialize)
    }

    fn value(&mut self, depth: usize) -> Result<Value> {
        if depth > MAX_DEPTH {
            return Err(Error::Unserialize);
        }
        match *self.data.get(self.pos).ok_or(Error::Unserialize)? {
            b'N' => {
                self.expect(b"N;")?;
                Ok(Value::Null)
            }
            b'b' => {
                self.expect(b"b:")?;
                match self.until(b';')? {
                    b"1" => Ok(Value::Bool(true)),
                    b"0" => Ok(Value::Bool(false)),
                    _ => Err(Error::Unserialize),
                }
            }
            b'i' => {
                self.expect(b"i:")?;
                Ok(Value::Int(self.int(b';')?))
            }
            b'd' => {
                self.expect(b"d:")?;
                Ok(Value::Float(parse_float(self.until(b';')?)?))
            }
            b's' => Ok(string_value(self.string()?)),
            b'a' => {
                self.expect(b"a:")?;
                let count = self.len(b':')?;
                let entries = self.entries(count, depth)?;
                Ok(assemble(entries))
            }
            b'O' => self.object(depth),
            _ => Err(Error::Unserialize),
        }
    }

    /// `s:<len>:"<bytes>";`
    fn string(&mut self) -> Result<&'a [u8]> {
        self.expect(b"s:")?;
        let len = self.len(b':')?;
        self.expect(b"\"")?;
        if len > self.remaining() {
            return Err(Error::Unserialize);
        }
        let bytes = &self.data[self.pos..self.pos + len];
        self.pos += len;
        self.expect(b"\";")?;
        Ok(bytes)
    }

    fn key(&mut self) -> Result<Key> {
        match self.data.get(self.pos) {
            Some(b'i') => {
                self.expect(b"i:")?;
                Ok(Key::Int(self.int(b';')?))
            }
            Some(b's') => {
                let bytes = self.string()?;
                String::from_utf8(bytes.to_vec())
                    .map(Key::String)
                    .map_err(|_| Error::Unserialize)
            }
            _ => Err(Error::Unserialize),
        }
    }

    /// `{<key><value>...}` with `count` pairs.
    fn entries(&mut self, count: usize, depth: usize) -> Result<Vec<(Key, Value)>> {
        self.expect(b"{")?;
        // Every pair takes at least 4 bytes ("i:0;N;"), so a hostile count cannot make us
        // reserve more than the input could hold.
        let mut entries = Vec::with_capacity(count.min(self.remaining() / 4));
        for _ in 0..count {
            let key = self.key()?;
            let value = self.value(depth + 1)?;
            entries.push((key, value));
        }
        self.expect(b"}")?;
        Ok(entries)
    }

    /// `O:<len>:"<class>":<count>:{...}`
    fn object(&mut self, depth: usize) -> Result<Value> {
        self.expect(b"O:")?;
        let len = self.len(b':')?;
        self.expect(b"\"")?;
        if len > self.remaining() {
            return Err(Error::Unserialize);
        }
        let class = String::from_utf8(self.data[self.pos..self.pos + len].to_vec())
            .map_err(|_| Error::Unserialize)?;
        self.pos += len;
        self.expect(b"\":")?;
        let count = self.len(b':')?;
        let properties = self.entries(count, depth)?;
        Ok(Value::Object { class, properties })
    }
}

fn string_value(bytes: &[u8]) -> Value {
    match std::str::from_utf8(bytes) {
        Ok(s) => Value::String(s.to_owned()),
        Err(_) => Value::Bytes(bytes.to_vec()),
    }
}

fn parse_float(raw: &[u8]) -> Result<f64> {
    match raw {
        b"INF" => return Ok(f64::INFINITY),
        b"-INF" => return Ok(f64::NEG_INFINITY),
        b"NAN" => return Ok(f64::NAN),
        _ => {}
    }
    // Rust's parser also accepts words like "inf" and "nan"; PHP does not.
    if raw.is_empty()
        || !raw
            .iter()
            .all(|b| b.is_ascii_digit() || matches!(b, b'+' | b'-' | b'.' | b'e' | b'E'))
    {
        return Err(Error::Unserialize);
    }
    std::str::from_utf8(raw)
        .ok()
        .and_then(|s| s.parse::<f64>().ok())
        .ok_or(Error::Unserialize)
}

/// A PHP array with the keys `0..n` in order is a list; anything else is a map.
fn assemble(entries: Vec<(Key, Value)>) -> Value {
    let is_list = entries
        .iter()
        .enumerate()
        .all(|(i, (k, _))| matches!(k, Key::Int(n) if usize::try_from(*n) == Ok(i)));
    if is_list {
        Value::List(entries.into_iter().map(|(_, v)| v).collect())
    } else {
        Value::Map(entries)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ser(v: &Value) -> String {
        String::from_utf8(serialize(v).unwrap()).unwrap()
    }

    fn unser(s: &str) -> Result<Value> {
        unserialize(s.as_bytes())
    }

    // Expected strings below are the output of PHP's serialize().

    #[test]
    fn serializes_scalars_like_php() {
        assert_eq!(ser(&Value::Null), "N;");
        assert_eq!(ser(&true.into()), "b:1;");
        assert_eq!(ser(&false.into()), "b:0;");
        assert_eq!(ser(&Value::Int(-42)), "i:-42;");
        assert_eq!(ser(&Value::Int(i64::MIN)), "i:-9223372036854775808;");
        assert_eq!(ser(&"héllo \"w\"".into()), "s:10:\"héllo \"w\"\";");
        assert_eq!(
            serialize(&Value::Bytes(vec![0, 0xff])).unwrap(),
            b"s:2:\"\0\xff\";"
        );
    }

    #[test]
    fn serializes_floats_like_php() {
        let cases = [
            (2.0, "d:2;"),
            (2.5, "d:2.5;"),
            (0.1, "d:0.1;"),
            (0.1 + 0.2, "d:0.30000000000000004;"),
            (100.0, "d:100;"),
            (0.5, "d:0.5;"),
            (1e14, "d:100000000000000;"),
            (1e15, "d:1000000000000000;"),
            (1e16, "d:10000000000000000;"),
            (1e17, "d:1.0E+17;"),
            (1e18, "d:1.0E+18;"),
            (123456789012345678.0, "d:1.2345678901234568E+17;"),
            (0.0001, "d:0.0001;"),
            (0.00009, "d:9.0E-5;"),
            (0.00001, "d:1.0E-5;"),
            (1.5e-7, "d:1.5E-7;"),
            (-1.5e25, "d:-1.5E+25;"),
            (5e-324, "d:5.0E-324;"),
            (f64::MAX, "d:1.7976931348623157E+308;"),
            (-0.0, "d:-0;"),
            (f64::INFINITY, "d:INF;"),
            (f64::NEG_INFINITY, "d:-INF;"),
            (f64::NAN, "d:NAN;"),
        ];
        for (f, want) in cases {
            assert_eq!(ser(&Value::Float(f)), want, "{f:?}");
        }
    }

    #[test]
    fn serializes_arrays_like_php() {
        assert_eq!(ser(&Value::List(vec![])), "a:0:{}");
        assert_eq!(
            ser(&Value::list([Value::from("x"), 1.into(), true.into()])),
            r#"a:3:{i:0;s:1:"x";i:1;i:1;i:2;b:1;}"#
        );
        // Order is kept; int and string keys can be mixed.
        let map = Value::Map(vec![(Key::Int(5), "a".into()), ("x".into(), Value::Null)]);
        assert_eq!(ser(&map), r#"a:2:{i:5;s:1:"a";s:1:"x";N;}"#);
    }

    #[test]
    fn objects_are_not_serializable() {
        let object = Value::Object {
            class: "stdClass".into(),
            properties: vec![],
        };
        assert_eq!(serialize(&object), Err(Error::Serialize));
        // Not even nested.
        assert_eq!(serialize(&Value::list([object])), Err(Error::Serialize));
    }

    #[test]
    fn unserializes_php_output() {
        assert_eq!(unser("N;"), Ok(Value::Null));
        assert_eq!(unser("b:1;"), Ok(Value::Bool(true)));
        assert_eq!(unser("i:7;"), Ok(Value::Int(7)));
        assert_eq!(unser("i:-9223372036854775808;"), Ok(Value::Int(i64::MIN)));
        assert_eq!(unser("d:2.5;"), Ok(Value::Float(2.5)));
        assert_eq!(unser("d:1.0E+25;"), Ok(Value::Float(1e25)));
        assert_eq!(unser("d:2;"), Ok(Value::Float(2.0)));
        assert_eq!(unser("d:INF;"), Ok(Value::Float(f64::INFINITY)));
        assert_eq!(unser("d:-INF;"), Ok(Value::Float(f64::NEG_INFINITY)));
        assert!(matches!(unser("d:NAN;"), Ok(Value::Float(f)) if f.is_nan()));
        // The length counts bytes, and the content may contain quotes and semicolons.
        assert_eq!(
            unser("s:14:\"héllo \"world\"\";"),
            Ok(Value::String("héllo \"world\"".into()))
        );
        assert_eq!(unser("s:0:\"\";"), Ok(Value::String(String::new())));
        assert_eq!(
            unser("s:2:\"\u{0}\u{0}\";"),
            Ok(Value::String("\0\0".into()))
        );
        assert_eq!(
            unserialize(b"s:2:\"\xff\xfe\";"),
            Ok(Value::Bytes(vec![0xff, 0xfe]))
        );
    }

    #[test]
    fn unserializes_lists_and_maps() {
        assert_eq!(unser("a:0:{}"), Ok(Value::List(vec![])));
        assert_eq!(
            unser(r#"a:2:{i:0;s:1:"x";i:1;a:1:{i:0;N;}}"#),
            Ok(Value::list([Value::from("x"), Value::list([Value::Null])]))
        );
        // Keys that are not 0..n in order make a map.
        for src in [
            r#"a:2:{i:1;s:1:"a";i:0;s:1:"b";}"#,
            r#"a:1:{i:1;s:1:"a";}"#,
            r#"a:1:{s:1:"0";s:1:"a";}"#,
        ] {
            assert!(matches!(unser(src), Ok(Value::Map(_))), "{src}");
        }
        assert_eq!(
            unser(r#"a:2:{s:1:"b";i:1;s:1:"a";i:2;}"#),
            Ok(Value::Map(vec![
                ("b".into(), Value::Int(1)),
                ("a".into(), Value::Int(2)),
            ]))
        );
    }

    #[test]
    fn unserializes_objects_without_instantiating() {
        let v = unser(r#"O:8:"stdClass":2:{s:1:"a";i:1;s:1:"b";s:3:"two";}"#).unwrap();
        assert_eq!(
            v,
            Value::Object {
                class: "stdClass".into(),
                properties: vec![("a".into(), Value::Int(1)), ("b".into(), "two".into())],
            }
        );
        // An unknown class is just a name.
        assert!(matches!(
            unser(r#"O:13:"Evil\Gadget\X":0:{}"#),
            Ok(Value::Object { class, .. }) if class == r"Evil\Gadget\X"
        ));
    }

    #[test]
    fn round_trips() {
        let values = [
            Value::Null,
            Value::Int(0),
            Value::Float(-3.25),
            Value::Float(1e300),
            Value::from("plain"),
            Value::Bytes(vec![0, 1, 2, 0xff]),
            Value::map([
                ("user", Value::from("alice")),
                ("tags", Value::list(["x", "y"])),
                ("meta", Value::Null),
            ]),
            Value::Map(vec![(3.into(), Value::list([1.5, 2.5]))]),
        ];
        for v in values {
            assert_eq!(unserialize(&serialize(&v).unwrap()), Ok(v));
        }
    }

    #[test]
    fn rejects_malformed_input() {
        let bad = [
            "",
            "x",
            "X;",
            "N",
            "N:",
            "b:",
            "b:2;",
            "b:1",
            "i:;",
            "i:abc;",
            "i:5",
            "i:9223372036854775808;",
            "d:;",
            "d:abc;",
            "d:inf;",
            "d:nan;",
            "d:infinity;",
            "d:5",
            "s:abc:\"x\";",
            "s:-1:\"\";",
            "s:2:ab\";",
            "s:2:\"ab",
            "s:2:\"ab\"",
            "s:5:\"ab\";",
            "s:99999999999999999999:\"ab\";",
            "a:x:{}",
            "a:-1:{}",
            "a:1:",
            "a:1:{i:0;}",
            "a:2:{i:0;b:1;}",
            "a:1:{i:0;b:1;",
            "a:1:{b:1;b:1;}",
            "a:1:{d:1.5;b:1;}",
            "a:1:{N;b:1;}",
            "O:abc:\"x\":0:{}",
            "O:8:\"stdClass\"",
            "O:3:abc\":1:{}",
            "O:3:\"abc\":x:{}",
            "O:99:\"abc\":0:{}",
            // Unsupported PHP features.
            "S:1:\"a\";",
            "C:3:\"Foo\":0:{}",
            "r:1;",
            "R:1;",
            "E:7:\"Foo:Bar\";",
        ];
        for src in bad {
            assert_eq!(unser(src), Err(Error::Unserialize), "{src:?}");
        }
    }

    #[test]
    fn rejects_trailing_data() {
        assert_eq!(unser("N;N;"), Err(Error::Unserialize));
        assert_eq!(unser("i:1;x"), Err(Error::Unserialize));
    }

    #[test]
    fn rejects_non_utf8_keys_and_class_names() {
        assert_eq!(
            unserialize(b"a:1:{s:1:\"\xff\";N;}"),
            Err(Error::Unserialize)
        );
        assert_eq!(unserialize(b"O:1:\"\xff\":0:{}"), Err(Error::Unserialize));
    }

    #[test]
    fn nesting_depth_is_limited_without_overflowing_the_stack() {
        let nested = |depth: usize| {
            let mut s = "a:1:{i:0;".repeat(depth);
            s.push_str("N;");
            s.push_str(&"}".repeat(depth));
            s
        };
        assert!(unser(&nested(MAX_DEPTH)).is_ok());
        assert_eq!(unser(&nested(MAX_DEPTH + 1)), Err(Error::Unserialize));
        assert_eq!(unser(&nested(100_000)), Err(Error::Unserialize));
    }

    #[test]
    fn hostile_element_counts_do_not_allocate_or_loop() {
        assert_eq!(unser("a:9223372036854775807:{}"), Err(Error::Unserialize));
        assert_eq!(unser("a:4000000000:{i:0;N;}"), Err(Error::Unserialize));
    }
}
