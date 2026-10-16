//! `CACHETTE__*` environment walker (plan task 5, Metis M16).
//!
//! Convention: scalar `CACHETTE__SECTION__KEY`; arrays = comma-separated
//! (`CACHETTE__AUTH__TOKENS="a,b"`); maps = JSON
//! (`CACHETTE__CLUSTER__SEED_FINGERPRINTS='{"a":"abc"}'`); a variable
//! without a section (`CACHETTE__KEY`) prefix-matches a unique field name.
//! Any `CACHETTE__*` variable that maps to no known key is an error.

use std::collections::BTreeMap;

use serde_json::Value;

use crate::config::error::ConfigError;

const PREFIX: &str = "CACHETTE__";

/// How a variable's raw string becomes a JSON value in the merged document.
#[derive(Clone, Copy, Debug)]
enum Kind {
    Str,
    U64,
    Bool,
    MinFree,
    StrList,
    StrMap,
}

struct Field {
    section: &'static [&'static str],
    key: &'static str,
    kind: Kind,
}

const fn field(section: &'static [&'static str], key: &'static str, kind: Kind) -> Field {
    Field { section, key, kind }
}

const FIELDS: &[Field] = &[
    field(&["server"], "listen", Kind::Str),
    field(&["server"], "external_url", Kind::Str),
    field(&["server"], "tls_cert", Kind::Str),
    field(&["server"], "tls_key", Kind::Str),
    field(&["server"], "max_chunk_bytes", Kind::U64),
    field(&["storage"], "backend", Kind::Str),
    field(&["storage", "fs"], "path", Kind::Str),
    field(&["storage", "fs"], "min_free", Kind::MinFree),
    field(&["cache"], "max_size", Kind::U64),
    field(&["cache"], "eviction", Kind::Str),
    field(&["cache"], "key_case", Kind::Str),
    field(&["cache"], "reservation_ttl_seconds", Kind::U64),
    field(&["auth"], "mode", Kind::Str),
    field(&["auth"], "secret", Kind::Str),
    field(&["auth"], "tokens", Kind::StrList),
    field(&["auth"], "hmac_max_age_seconds", Kind::U64),
    field(&["v1"], "signed_url_ttl_seconds", Kind::U64),
    field(&["v2"], "jwt_secret", Kind::Str),
    field(&["v2"], "jwt_ttl_seconds", Kind::U64),
    field(&["cluster"], "enabled", Kind::Bool),
    field(&["cluster"], "node_id", Kind::Str),
    field(&["cluster"], "advertise_addr", Kind::Str),
    field(&["cluster"], "mdns", Kind::Bool),
    field(&["cluster"], "seeds", Kind::StrList),
    field(&["cluster"], "seed_fingerprints", Kind::StrMap),
    field(&["cluster"], "tiebreak", Kind::Str),
    field(&["cluster"], "cert_path", Kind::Str),
    field(&["cluster"], "heartbeat_interval_seconds", Kind::U64),
    field(&["cluster"], "peer_timeout_seconds", Kind::U64),
    field(&["log"], "level", Kind::Str),
    field(&["log"], "format", Kind::Str),
    field(&["log"], "file", Kind::Str),
];

/// Overlay every `CACHETTE__*` pair onto the merged config document.
pub(crate) fn apply(doc: &mut Value, env: &[(&str, &str)]) -> Result<(), ConfigError> {
    for (name, raw) in env {
        let Some(head) = name.get(..PREFIX.len()) else {
            continue;
        };
        if !head.eq_ignore_ascii_case(PREFIX) {
            continue;
        }
        let rest = &name[PREFIX.len()..];
        let target = resolve_field(name, rest)?;
        let value = coerce(target.kind, name, raw)?;
        insert(doc, name, target, value)?;
    }
    Ok(())
}

/// Map a `CACHETTE__*` variable to a schema field, or reject. `name` is the
/// full variable, `rest` is the part after the `CACHETTE__` prefix.
fn resolve_field<'f>(name: &str, rest: &str) -> Result<&'f Field, ConfigError> {
    let unknown = || ConfigError::UnknownEnvVar(name.to_owned());
    if let Some(found) = FIELDS
        .iter()
        .find(|candidate| env_name(candidate).eq_ignore_ascii_case(name))
    {
        return Ok(found);
    }
    if rest.contains("__") {
        return Err(unknown());
    }
    match FIELDS
        .iter()
        .filter(|candidate| candidate.key.eq_ignore_ascii_case(rest))
        .collect::<Vec<_>>()
        .as_slice()
    {
        [unique] => Ok(unique),
        _ => Err(unknown()),
    }
}

/// Full conventional variable name for a field, e.g. `CACHETTE__SERVER__LISTEN`.
fn env_name(target: &Field) -> String {
    let mut name = String::from(PREFIX);
    for segment in target.section {
        name.push_str(&segment.to_uppercase());
        name.push_str("__");
    }
    name.push_str(&target.key.to_uppercase());
    name
}

/// Set `section.../key = value` inside the document, creating tables as needed.
fn insert(doc: &mut Value, name: &str, target: &Field, value: Value) -> Result<(), ConfigError> {
    let not_a_table = |section: &str| ConfigError::InvalidEnvValue {
        var: name.to_owned(),
        msg: format!("config section [{section}] is not a table"),
    };
    let mut cursor = doc;
    for segment in target.section {
        cursor = cursor
            .as_object_mut()
            .ok_or_else(|| not_a_table(&target.section.join(".")))?
            .entry((*segment).to_owned())
            .or_insert_with(|| Value::Object(serde_json::Map::new()));
    }
    cursor
        .as_object_mut()
        .ok_or_else(|| not_a_table(&target.section.join(".")))?
        .insert(target.key.to_owned(), value);
    Ok(())
}

/// Parse the raw string according to the field kind. Every failure names
/// the offending variable (M16).
fn coerce(kind: Kind, name: &str, raw: &str) -> Result<Value, ConfigError> {
    let invalid = |msg: String| ConfigError::InvalidEnvValue {
        var: name.to_owned(),
        msg,
    };
    match kind {
        Kind::Str => Ok(Value::String(raw.to_owned())),
        Kind::U64 => raw
            .parse::<u64>()
            .map(Value::from)
            .map_err(|_| invalid(format!("expected an unsigned integer, got {raw:?}"))),
        Kind::Bool => raw
            .parse::<bool>()
            .map(Value::from)
            .map_err(|_| invalid(format!("expected true or false, got {raw:?}"))),
        Kind::MinFree => match raw.parse::<f64>() {
            Ok(number) if number.is_finite() => serde_json::Number::from_f64(number)
                .map(Value::Number)
                .ok_or_else(|| invalid(format!("cannot represent {number} as a number"))),
            _ => Ok(Value::String(raw.to_owned())),
        },
        Kind::StrList => Ok(Value::Array(
            raw.split(',')
                .map(str::trim)
                .filter(|item| !item.is_empty())
                .map(|item| Value::String(item.to_owned()))
                .collect(),
        )),
        Kind::StrMap => {
            let map: BTreeMap<String, String> = serde_json::from_str(raw).map_err(|err| {
                invalid(format!(
                    "expected a JSON object of string values, got {raw:?}: {err}"
                ))
            })?;
            let mut object = serde_json::Map::new();
            for (key, value) in map {
                object.insert(key, Value::String(value));
            }
            Ok(Value::Object(object))
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn apply_one(name: &str, raw: &str) -> Result<Value, ConfigError> {
        let mut doc = Value::Object(serde_json::Map::new());
        apply(&mut doc, &[(name, raw)])?;
        Ok(doc)
    }

    #[test]
    fn unknown_variables_are_rejected_and_named() {
        let sectioned = apply_one("CACHETTE__NOPE__BAD", "1").expect_err("unknown section");
        assert!(
            matches!(
                &sectioned,
                ConfigError::UnknownEnvVar(var) if var == "CACHETTE__NOPE__BAD"
            ),
            "unexpected error: {sectioned:?}"
        );
        assert!(sectioned.to_string().contains("CACHETTE__NOPE__BAD"));

        let bare = apply_one("CACHETTE__NOPE", "1").expect_err("unknown key");
        assert!(
            matches!(&bare, ConfigError::UnknownEnvVar(var) if var == "CACHETTE__NOPE"),
            "unexpected error: {bare:?}"
        );

        let dotted = apply_one("CACHETTE__FS__PATH", "/tmp").expect_err("no such section");
        assert!(
            matches!(&dotted, ConfigError::UnknownEnvVar(var) if var == "CACHETTE__FS__PATH"),
            "unexpected error: {dotted:?}"
        );
    }

    #[test]
    fn full_names_match_ignoring_case_and_unprefixed_vars_are_skipped() {
        let full = apply_one("CACHETTE__SERVER__LISTEN", "127.0.0.1:9000").expect("applies");
        assert_eq!(full["server"]["listen"], "127.0.0.1:9000");

        let lower = apply_one("cachette__server__listen", "127.0.0.1:9001").expect("applies");
        assert_eq!(lower["server"]["listen"], "127.0.0.1:9001");

        let mut doc = Value::Object(serde_json::Map::new());
        apply(&mut doc, &[("PATH", "/bin"), ("LANG", "C")]).expect("non-prefixed vars are skipped");
        assert_eq!(doc, json!({}));
    }

    #[test]
    fn bare_unique_key_prefix_matches_its_section() {
        let listen = apply_one("CACHETTE__LISTEN", "127.0.0.1:9002").expect("applies");
        assert_eq!(listen["server"]["listen"], "127.0.0.1:9002");

        let enabled = apply_one("CACHETTE__ENABLED", "true").expect("applies");
        assert_eq!(enabled["cluster"]["enabled"], json!(true));
    }

    #[test]
    fn array_values_are_comma_split_trimmed_and_empty_free() {
        let doc = apply_one("CACHETTE__AUTH__TOKENS", "a, b ,,c ,").expect("applies");
        assert_eq!(doc["auth"]["tokens"], json!(["a", "b", "c"]));
    }

    #[test]
    fn map_values_parse_as_json_string_objects() {
        let doc = apply_one(
            "CACHETTE__CLUSTER__SEED_FINGERPRINTS",
            "{\"p1\":\"aa\",\"p2\":\"bb\"}",
        )
        .expect("applies");
        assert_eq!(
            doc["cluster"]["seed_fingerprints"],
            json!({"p1": "aa", "p2": "bb"})
        );

        let err = apply_one("CACHETTE__CLUSTER__SEED_FINGERPRINTS", "not-json")
            .expect_err("rejects non-JSON");
        assert!(
            matches!(
                &err,
                ConfigError::InvalidEnvValue { var, .. }
                    if var == "CACHETTE__CLUSTER__SEED_FINGERPRINTS"
            ),
            "unexpected error: {err:?}"
        );
        assert!(
            err.to_string()
                .contains("CACHETTE__CLUSTER__SEED_FINGERPRINTS")
        );
    }

    #[test]
    fn scalar_coercions_cover_bool_u64_and_min_free() {
        let off = apply_one("CACHETTE__CLUSTER__ENABLED", "false").expect("applies");
        assert_eq!(off["cluster"]["enabled"], json!(false));
        let bad_bool = apply_one("CACHETTE__CLUSTER__ENABLED", "yes").expect_err("rejects");
        assert!(
            matches!(
                &bad_bool,
                ConfigError::InvalidEnvValue { var, .. } if var == "CACHETTE__CLUSTER__ENABLED"
            ),
            "unexpected error: {bad_bool:?}"
        );
        assert!(bad_bool.to_string().contains("CACHETTE__CLUSTER__ENABLED"));

        let size = apply_one("CACHETTE__CACHE__MAX_SIZE", "1234").expect("applies");
        assert_eq!(size["cache"]["max_size"], json!(1234));
        let bad_u64 = apply_one("CACHETTE__CACHE__MAX_SIZE", "big").expect_err("rejects");
        assert!(
            matches!(
                &bad_u64,
                ConfigError::InvalidEnvValue { var, .. } if var == "CACHETTE__CACHE__MAX_SIZE"
            ),
            "unexpected error: {bad_u64:?}"
        );

        // MinFree: a plain number stays a number, other forms stay strings
        // for `MinFree` to re-parse during section deserialization.
        let fraction = apply_one("CACHETTE__STORAGE__FS__MIN_FREE", "0.5").expect("applies");
        assert_eq!(fraction["storage"]["fs"]["min_free"], json!(0.5));
        let percent = apply_one("CACHETTE__STORAGE__FS__MIN_FREE", "20%").expect("applies");
        assert_eq!(percent["storage"]["fs"]["min_free"], json!("20%"));
        let bytes = apply_one("CACHETTE__STORAGE__FS__MIN_FREE", "2GiB").expect("applies");
        assert_eq!(bytes["storage"]["fs"]["min_free"], json!("2GiB"));
    }
}
