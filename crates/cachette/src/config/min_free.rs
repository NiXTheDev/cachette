//! `min_free` value: a fraction, a percent string, or a bytesize string.
//!
//! Per the config spec, byte suffixes are ALWAYS 1024-based: `"2GiB"` and
//! `"2GB"` both mean `2 * 1024^3` bytes (Metis B3 capacity model).

use std::fmt;
use std::str::FromStr;

use serde::Deserialize;
use serde::Deserializer;
use serde::Serialize;
use serde::Serializer;

use crate::config::error::ConfigError;

/// Free-space floor for the capacity model (see plan B3).
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum MinFree {
    /// Fraction of total: `0.2` = 20% of the volume. Range `[0, 1]`.
    Fraction(f64),
    /// Percent of total: `"20%"` = `0.2`. Range `[0, 100]`.
    Percent(f64),
    /// Absolute bytes: `"2GiB"` = `2 * 1024^3`.
    Bytes(u64),
}

impl MinFree {
    /// Resolve against a `total_bytes` disk size (B3: `free < min_free`
    /// triggers eviction; the floor is a byte count once a total is known).
    #[must_use]
    pub fn resolve(self, total_bytes: u64) -> u64 {
        match self {
            Self::Fraction(f) => (f * total_bytes as f64) as u64,
            Self::Percent(p) => ((p / 100.0) * total_bytes as f64) as u64,
            Self::Bytes(b) => b,
        }
    }

    /// Parse a `min_free` string form (`"20%"` / `"2GiB"` / `"2GB"`).
    pub fn parse_str(raw: &str) -> Result<Self, ConfigError> {
        let bad = |msg: &str| ConfigError::MinFree {
            value: raw.to_owned(),
            msg: msg.to_owned(),
        };
        let trimmed = raw.trim();
        if let Some(percent) = trimmed.strip_suffix('%') {
            let value: f64 = percent
                .trim()
                .parse()
                .map_err(|_| bad("expected a number before '%', e.g. \"20%\""))?;
            if value.is_finite() && (0.0..=100.0).contains(&value) {
                return Ok(Self::Percent(value));
            }
            return Err(bad("percent must be a finite number in [0, 100]"));
        }
        if let Ok(value) = trimmed.parse::<f64>() {
            return Self::fraction(value)
                .ok_or_else(|| bad("fraction must be a finite number in [0, 1]"));
        }
        Self::parse_bytes(trimmed).ok_or_else(|| {
            bad(
                "expected a fraction (0.2), a percent (\"20%\"), or a bytesize \
                 (\"2GiB\" or \"2GB\", always 1024-based)",
            )
        })
    }

    /// Validate a fraction (rejects negative, NaN, and > 1 per spec).
    fn fraction(value: f64) -> Option<Self> {
        if value.is_finite() && (0.0..=1.0).contains(&value) {
            Some(Self::Fraction(value))
        } else {
            None
        }
    }

    /// Parse a bytesize: `<digits><suffix>` with a 1024-based suffix.
    fn parse_bytes(raw: &str) -> Option<Self> {
        let index = raw.find(|c: char| !c.is_ascii_digit())?;
        if index == 0 {
            return None;
        }
        let multiplier = match raw[index..].to_ascii_lowercase().as_str() {
            "kb" | "kib" => 1024u64,
            "mb" | "mib" => 1024 * 1024,
            "gb" | "gib" => 1024 * 1024 * 1024,
            "tb" | "tib" => 1024 * 1024 * 1024 * 1024,
            _ => return None,
        };
        let value: u64 = raw[..index].parse().ok()?;
        Some(Self::Bytes(value.checked_mul(multiplier)?))
    }
}

impl FromStr for MinFree {
    type Err = ConfigError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse_str(s)
    }
}

/// Deserialize from a JSON/TOML number (fraction) or string (`"20%"`,
/// `"2GiB"`). Range checks live in `parse_str`/`fraction` so both input
/// paths enforce the same rules.
impl<'de> Deserialize<'de> for MinFree {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct MinFreeVisitor;

        impl serde::de::Visitor<'_> for MinFreeVisitor {
            type Value = MinFree;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a fraction, percent (\"20%\"), or bytesize (\"2GiB\") string")
            }

            fn visit_f64<E: serde::de::Error>(self, value: f64) -> Result<Self::Value, E> {
                MinFree::fraction(value).ok_or_else(|| {
                    E::custom(format!(
                        "min_free fraction must be a finite number in [0, 1], got {value}"
                    ))
                })
            }

            fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<Self::Value, E> {
                self.visit_f64(value as f64)
            }

            fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<Self::Value, E> {
                self.visit_f64(value as f64)
            }

            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
                MinFree::parse_str(value).map_err(|err| E::custom(err.to_string()))
            }
        }

        deserializer.deserialize_any(MinFreeVisitor)
    }
}

/// Serialize back in its authored form: fraction as a number, percent as
/// `"NN%"`, bytesize as a number of bytes (deterministic for `--print-config`).
impl Serialize for MinFree {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Fraction(f) => serializer.serialize_f64(*f),
            Self::Percent(p) => serializer.serialize_str(&format!("{p}%")),
            Self::Bytes(b) => serializer.serialize_u64(*b),
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const GIB: u64 = 1024 * 1024 * 1024;

    fn parse(raw: &str) -> Result<MinFree, ConfigError> {
        MinFree::parse_str(raw)
    }

    #[test]
    fn parses_fraction_within_0_and_1() {
        assert_eq!(parse("0.2").ok(), Some(MinFree::Fraction(0.2)));
        assert_eq!(parse(" 0.2 ").ok(), Some(MinFree::Fraction(0.2)));
        assert_eq!(parse("0").ok(), Some(MinFree::Fraction(0.0)));
        assert_eq!(parse("1").ok(), Some(MinFree::Fraction(1.0)));
    }

    #[test]
    fn rejects_fractions_outside_range_and_non_finite() {
        for raw in ["-0.1", "1.5", "NaN", "inf", "-inf"] {
            let err = parse(raw).expect_err("out-of-range fraction");
            assert!(
                matches!(&err, ConfigError::MinFree { value, .. } if value == raw),
                "unexpected error: {err:?}"
            );
            let message = err.to_string();
            assert!(message.contains("min_free"), "{message}");
            assert!(message.contains("fraction"), "{message}");
        }
    }

    #[test]
    fn parses_percent_within_0_and_100() {
        assert_eq!(parse("20%").ok(), Some(MinFree::Percent(20.0)));
        assert_eq!(parse(" 20% ").ok(), Some(MinFree::Percent(20.0)));
        assert_eq!(parse("0%").ok(), Some(MinFree::Percent(0.0)));
        assert_eq!(parse("100%").ok(), Some(MinFree::Percent(100.0)));
        assert_eq!(parse("12.5%").ok(), Some(MinFree::Percent(12.5)));
    }

    #[test]
    fn rejects_percents_outside_range_or_malformed() {
        for raw in ["101%", "-5%", "abc%", "%", "NaN%"] {
            let err = parse(raw).expect_err("invalid percent");
            assert!(
                matches!(&err, ConfigError::MinFree { value, .. } if value == raw),
                "unexpected error: {err:?}"
            );
        }
        let message = parse("101%").expect_err("out of range").to_string();
        assert!(message.contains("[0, 100]"), "{message}");
    }

    #[test]
    fn parses_bytesize_with_1024_based_suffixes() {
        assert_eq!(parse("2GiB").ok(), Some(MinFree::Bytes(2 * GIB)));
        assert_eq!(parse("2GB").ok(), Some(MinFree::Bytes(2 * GIB)));
        assert_eq!(parse("1KiB").ok(), Some(MinFree::Bytes(1024)));
        assert_eq!(parse("1KB").ok(), Some(MinFree::Bytes(1024)));
        assert_eq!(parse("1MiB").ok(), Some(MinFree::Bytes(1024 * 1024)));
        assert_eq!(
            parse("1TiB").ok(),
            Some(MinFree::Bytes(1024 * 1024 * 1024 * 1024))
        );
        assert_eq!(parse("512kb").ok(), Some(MinFree::Bytes(512 * 1024)));
    }

    #[test]
    fn rejects_unrecognized_bytesizes() {
        for raw in ["2XB", "GiB", "-1GiB", "2GiBextra", ""] {
            let err = parse(raw).expect_err("invalid bytesize");
            assert!(
                matches!(&err, ConfigError::MinFree { value, .. } if value == raw),
                "unexpected error: {err:?}"
            );
        }
        let message = parse("2XB").expect_err("unknown suffix").to_string();
        assert!(message.contains("bytesize"), "{message}");
    }

    #[test]
    fn resolves_each_form_against_total_bytes() {
        assert_eq!(MinFree::Fraction(0.2).resolve(1_000_000), 200_000);
        assert_eq!(MinFree::Percent(20.0).resolve(1_000_000), 200_000);
        assert_eq!(MinFree::Percent(12.5).resolve(8_000), 1_000);
        assert_eq!(MinFree::Bytes(4_096).resolve(u64::MAX), 4_096);
    }

    #[test]
    fn deserializes_from_numbers_and_strings_with_range_checks() {
        let fraction: MinFree = serde_json::from_str("0.2").expect("number fraction");
        assert_eq!(fraction, MinFree::Fraction(0.2));
        let integer: MinFree = serde_json::from_str("1").expect("integer fraction");
        assert_eq!(integer, MinFree::Fraction(1.0));
        let percent: MinFree = serde_json::from_str("\"20%\"").expect("percent string");
        assert_eq!(percent, MinFree::Percent(20.0));
        let bytes: MinFree = serde_json::from_str("\"2GiB\"").expect("bytesize string");
        assert_eq!(bytes, MinFree::Bytes(2 * GIB));

        let bad_number = serde_json::from_str::<MinFree>("1.5").expect_err("fraction too big");
        assert!(bad_number.to_string().contains("[0, 1]"), "{bad_number}");
        let bad_percent = serde_json::from_str::<MinFree>("\"101%\"").expect_err("percent too big");
        assert!(
            bad_percent.to_string().contains("min_free"),
            "{bad_percent}"
        );
        let bad_bytes = serde_json::from_str::<MinFree>("\"abc\"").expect_err("not parseable");
        assert!(bad_bytes.to_string().contains("min_free"), "{bad_bytes}");
    }

    #[test]
    fn serializes_back_in_authored_form() {
        assert_eq!(
            serde_json::to_value(MinFree::Fraction(0.2)).expect("serializes"),
            json!(0.2)
        );
        assert_eq!(
            serde_json::to_value(MinFree::Percent(20.0)).expect("serializes"),
            json!("20%")
        );
        assert_eq!(
            serde_json::to_value(MinFree::Bytes(1024)).expect("serializes"),
            json!(1024)
        );
    }

    #[test]
    fn serde_round_trips_each_form() {
        for original in [MinFree::Fraction(0.2), MinFree::Percent(20.0)] {
            let value = serde_json::to_value(original).expect("serializes");
            let round_tripped: MinFree = serde_json::from_value(value).expect("deserializes");
            assert_eq!(round_tripped, original);
        }
    }

    #[test]
    fn from_str_delegates_to_parse_str() {
        assert_eq!("20%".parse::<MinFree>().ok(), Some(MinFree::Percent(20.0)));
        assert_eq!(
            "2GiB".parse::<MinFree>().ok(),
            Some(MinFree::Bytes(2 * GIB))
        );
        assert!("bogus".parse::<MinFree>().is_err());
    }
}
