//! A git revision, parsed-not-validated: a [`Rev`] value is a proof that
//! the string is a 40-char lowercase-hex object id. Illegal revisions
//! have no constructor other than the rejecting parse boundary — the
//! `fail-closed` invariant starts here (an unresolvable/garbage HEAD
//! never becomes a `Rev`, so it can never reach a build or an
//! activation).

use serde::{Deserialize, Serialize};
use std::fmt;

/// A validated 40-hex git object id.
///
/// Construct only via [`Rev::parse`] (or deserialization, which routes
/// through the same check). The inner string is private, so no code path
/// produces a `Rev` that isn't 40 lowercase-hex chars.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct Rev(String);

/// Why a string is not a valid [`Rev`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RevError {
    /// Not exactly 40 characters.
    #[error("revision must be 40 hex chars, got {0}")]
    BadLength(usize),
    /// Contains a non-`[0-9a-f]` character.
    #[error("revision contains a non-hex character: {0:?}")]
    NonHex(char),
}

impl Rev {
    /// Parse a full 40-char lowercase-hex object id. Trims surrounding
    /// whitespace first (ls-remote output carries a trailing newline).
    ///
    /// # Errors
    /// [`RevError`] if the trimmed input is not 40 lowercase-hex chars.
    pub fn parse(s: &str) -> Result<Self, RevError> {
        let s = s.trim();
        if s.len() != 40 {
            return Err(RevError::BadLength(s.len()));
        }
        if let Some(c) = s.chars().find(|c| !matches!(c, '0'..='9' | 'a'..='f')) {
            return Err(RevError::NonHex(c));
        }
        Ok(Self(s.to_owned()))
    }

    /// The full 40-char id.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The 7-char short id (for logs/receipts display).
    #[must_use]
    pub fn short(&self) -> &str {
        &self.0[..7]
    }
}

impl fmt::Display for Rev {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Rev {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(d)?;
        Rev::parse(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OK: &str = "0123456789abcdef0123456789abcdef01234567";

    #[test]
    fn parses_valid() {
        let r = Rev::parse(OK).unwrap();
        assert_eq!(r.as_str(), OK);
        assert_eq!(r.short(), "0123456");
    }

    #[test]
    fn trims_whitespace() {
        assert_eq!(Rev::parse(&format!("  {OK}\n")).unwrap().as_str(), OK);
    }

    #[test]
    fn rejects_short() {
        assert_eq!(Rev::parse("abc").unwrap_err(), RevError::BadLength(3));
    }

    #[test]
    fn rejects_long() {
        assert!(matches!(Rev::parse(&"a".repeat(41)).unwrap_err(), RevError::BadLength(41)));
    }

    #[test]
    fn rejects_uppercase() {
        // Uppercase is non-canonical for git object ids — reject.
        assert!(matches!(
            Rev::parse("0123456789ABCDEF0123456789abcdef01234567").unwrap_err(),
            RevError::NonHex('A')
        ));
    }

    #[test]
    fn rejects_nonhex() {
        assert!(matches!(
            Rev::parse("z123456789abcdef0123456789abcdef01234567").unwrap_err(),
            RevError::NonHex('z')
        ));
    }

    #[test]
    fn rejects_empty() {
        assert_eq!(Rev::parse("").unwrap_err(), RevError::BadLength(0));
    }

    #[test]
    fn serde_roundtrip_and_rejects_bad_json() {
        let r = Rev::parse(OK).unwrap();
        let json = serde_json::to_string(&r).unwrap();
        assert_eq!(json, format!("\"{OK}\""));
        assert_eq!(serde_json::from_str::<Rev>(&json).unwrap(), r);
        // Deserialization routes through the same validation.
        assert!(serde_json::from_str::<Rev>("\"nope\"").is_err());
    }
}
