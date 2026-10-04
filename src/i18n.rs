// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 EON contributors
//
// Additional permission under GNU GPL version 3 section 7:
// see LICENSE-EXCEPTION.md (EON Module ABI Exception 1.0).

//! Messages, in Turkish and English.
//!
//! The plan's rule is "i18n from the start: no user-visible text is embedded
//! in code, translation files are separate" (madde 40). That rule is cheap to
//! follow now and expensive to retrofit — by the time an interface exists,
//! every string has grown a format call around it — so the machinery lands
//! with the headless build even though nothing draws a window yet.
//!
//! Turkish and English ship in v1 and both live in `i18n/`, loaded at compile
//! time so a build is one file and a missing catalogue is impossible.
//!
//! ## Placeholders are positional
//!
//! `{0}`, `{1}`, and `{{` for a literal brace. Positional rather than named
//! because word order is exactly what differs between these two languages:
//! "3 addons installed" against "3 eklenti kurulu" is fine, but the moment a
//! message has two substitutions the translator needs to reorder them, and a
//! named scheme that cannot reorder is a scheme that produces translations
//! nobody would say out loud.
//!
//! ## A missing translation falls back and says nothing
//!
//! English is the fallback. A key missing from the Turkish catalogue yields
//! the English text rather than an error or a visible marker: the user wanted
//! to read something, and a half-translated sentence beats `??key??`. What
//! stops that from becoming an excuse is [`audit`], which a test runs over
//! both catalogues — so a missing key is a build failure for us and a silent
//! fallback for the user, which is the right way round.

use std::collections::BTreeMap;

use crate::error::{Error, Result};

/// The locale used when nothing else is available.
pub const FALLBACK_LOCALE: &str = "en";

/// Locales this build ships.
pub const SHIPPED_LOCALES: &[&str] = &["en", "tr"];

const EN: &str = include_str!("../i18n/en.json");
const TR: &str = include_str!("../i18n/tr.json");

/// One locale's messages.
#[derive(Debug, Clone)]
pub struct Catalog {
    locale: String,
    messages: BTreeMap<String, String>,
}

impl Catalog {
    /// Parse a catalogue document: a flat JSON object of key to text.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidSettings`] if the document is not a flat object of
    /// strings. Nested objects are refused rather than flattened, so a key is
    /// always exactly what the code asks for.
    pub fn parse(locale: impl Into<String>, text: &str) -> Result<Self> {
        let raw: BTreeMap<String, serde_json::Value> = serde_json::from_str(text).map_err(|e| {
            Error::InvalidSettings(format!("message catalogue is not a JSON object: {e}"))
        })?;
        let mut messages = BTreeMap::new();
        for (key, value) in raw {
            match value {
                serde_json::Value::String(text) => {
                    messages.insert(key, text);
                }
                other => {
                    return Err(Error::InvalidSettings(format!(
                        "message '{key}' is {}, not a string",
                        match other {
                            serde_json::Value::Object(_) => "an object",
                            serde_json::Value::Array(_) => "an array",
                            serde_json::Value::Null => "null",
                            _ => "not text",
                        }
                    )))
                }
            }
        }
        Ok(Self {
            locale: locale.into(),
            messages,
        })
    }

    /// Which locale this is.
    #[must_use]
    pub fn locale(&self) -> &str {
        &self.locale
    }

    /// The text for `key`, if this catalogue has it.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&str> {
        self.messages.get(key).map(String::as_str)
    }

    /// Every key, sorted.
    #[must_use]
    pub fn keys(&self) -> Vec<&str> {
        self.messages.keys().map(String::as_str).collect()
    }

    /// How many messages it holds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.messages.len()
    }

    /// Whether it holds nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.messages.is_empty()
    }
}

/// A locale with its fallback behind it.
#[derive(Debug, Clone)]
pub struct Messages {
    primary: Catalog,
    fallback: Catalog,
}

impl Messages {
    /// The catalogues for `locale`, falling back to English.
    ///
    /// Accepts a full tag and narrows: `tr-TR` resolves to `tr`, because a
    /// region nobody wrote a catalogue for should still get the language that
    /// was written.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidSettings`] only if a shipped catalogue is malformed,
    /// which would be a build problem rather than a runtime one. An unknown
    /// locale is not an error: it yields English.
    pub fn for_locale(locale: &str) -> Result<Self> {
        let fallback = Catalog::parse(FALLBACK_LOCALE, EN)?;
        let language = locale.split('-').next().unwrap_or(locale);
        let primary = match language {
            "tr" => Catalog::parse("tr", TR)?,
            // English, and every locale nobody has written a catalogue for
            // yet: the fallback, with no complaint. The user asked to read
            // something.
            _ => fallback.clone(),
        };
        Ok(Self { primary, fallback })
    }

    /// Which locale is in use.
    #[must_use]
    pub fn locale(&self) -> &str {
        self.primary.locale()
    }

    /// The text for `key`.
    ///
    /// Falls back to English, then to the key itself. Returning the key is the
    /// last resort and is deliberately recognisable: it means code asked for a
    /// message that no catalogue has, which [`audit`] turns into a test
    /// failure before a user ever sees it.
    /// The returned reference borrows from the catalogues *or* from `key`,
    /// which is why both share a lifetime: the last-resort return value is the
    /// key the caller passed in.
    #[must_use]
    pub fn get<'a>(&'a self, key: &'a str) -> &'a str {
        self.primary
            .get(key)
            .or_else(|| self.fallback.get(key))
            .unwrap_or(key)
    }

    /// The text for `key` with `{0}`-style placeholders substituted.
    ///
    /// An index with no argument is left as written rather than dropped: a
    /// visible `{1}` in a message is a bug report, while a silently missing
    /// value is a sentence that reads fine and says something false.
    #[must_use]
    pub fn format(&self, key: &str, arguments: &[&str]) -> String {
        interpolate(self.get(key), arguments)
    }

    /// Whether the primary catalogue has its own text for `key`, rather than
    /// falling back.
    #[must_use]
    pub fn is_translated(&self, key: &str) -> bool {
        self.primary.get(key).is_some()
    }
}

/// Substitute `{0}`, `{1}` … and collapse `{{` to `{`.
fn interpolate(template: &str, arguments: &[&str]) -> String {
    let mut out = String::with_capacity(template.len());
    let mut chars = template.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '}' {
            // `}}` is a literal `}`, matching `{{`. Without this the pair in
            // `{{0}}` collapses on the left and doubles on the right.
            if chars.peek() == Some(&'}') {
                chars.next();
            }
            out.push('}');
            continue;
        }
        if ch != '{' {
            out.push(ch);
            continue;
        }
        if chars.peek() == Some(&'{') {
            chars.next();
            out.push('{');
            continue;
        }
        // Read digits up to the closing brace.
        let mut digits = String::new();
        let mut closed = false;
        while let Some(&next) = chars.peek() {
            if next == '}' {
                chars.next();
                closed = true;
                break;
            }
            if !next.is_ascii_digit() {
                break;
            }
            digits.push(next);
            chars.next();
        }
        match (closed, digits.parse::<usize>()) {
            (true, Ok(index)) => {
                if let Some(value) = arguments.get(index) {
                    out.push_str(value);
                } else {
                    // Left visible on purpose: a bug report beats a sentence
                    // that reads fine and says something false.
                    use std::fmt::Write as _;
                    let _ = write!(out, "{{{index}}}");
                }
            }
            // Not a placeholder at all; put back what was consumed.
            _ => {
                out.push('{');
                out.push_str(&digits);
                if closed {
                    out.push('}');
                }
            }
        }
    }
    out
}

/// What is wrong with a set of catalogues.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditReport {
    /// Keys in the fallback catalogue that a translation is missing.
    pub missing: Vec<String>,
    /// Keys a translation has that the fallback does not — a stale entry, or a
    /// typo in a key that will therefore never be read.
    pub extra: Vec<String>,
    /// Keys whose placeholder sets differ between the two. This is the finding
    /// that matters most: a translation missing a `{0}` silently drops a value
    /// out of a sentence.
    pub placeholder_mismatch: Vec<String>,
    /// Keys whose text is empty in a translation.
    pub empty: Vec<String>,
}

impl AuditReport {
    /// Whether the translation is complete and consistent.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.missing.is_empty()
            && self.extra.is_empty()
            && self.placeholder_mismatch.is_empty()
            && self.empty.is_empty()
    }

    /// A readable summary for a test failure or a tooling report.
    #[must_use]
    pub fn describe(&self) -> String {
        let mut lines = Vec::new();
        for (label, keys) in [
            ("missing", &self.missing),
            ("not in the fallback", &self.extra),
            ("placeholders differ", &self.placeholder_mismatch),
            ("empty", &self.empty),
        ] {
            if !keys.is_empty() {
                lines.push(format!("{label}: {}", keys.join(", ")));
            }
        }
        if lines.is_empty() {
            "complete".to_owned()
        } else {
            lines.join("; ")
        }
    }
}

/// Compare a translation against the fallback catalogue.
#[must_use]
pub fn audit(fallback: &Catalog, translation: &Catalog) -> AuditReport {
    let mut missing = Vec::new();
    let mut placeholder_mismatch = Vec::new();
    let mut empty = Vec::new();

    for key in fallback.keys() {
        match translation.get(key) {
            None => missing.push(key.to_owned()),
            Some(text) if text.trim().is_empty() => empty.push(key.to_owned()),
            Some(text) => {
                let Some(source) = fallback.get(key) else {
                    continue;
                };
                if placeholders(source) != placeholders(text) {
                    placeholder_mismatch.push(key.to_owned());
                }
            }
        }
    }
    let extra = translation
        .keys()
        .into_iter()
        .filter(|key| fallback.get(key).is_none())
        .map(ToOwned::to_owned)
        .collect();

    AuditReport {
        missing,
        extra,
        placeholder_mismatch,
        empty,
    }
}

/// The set of placeholder indices a message uses.
fn placeholders(template: &str) -> std::collections::BTreeSet<usize> {
    let mut found = std::collections::BTreeSet::new();
    let mut chars = template.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch != '{' {
            continue;
        }
        if chars.peek() == Some(&'{') {
            chars.next();
            continue;
        }
        let mut digits = String::new();
        let mut closed = false;
        while let Some(&next) = chars.peek() {
            if next == '}' {
                chars.next();
                closed = true;
                break;
            }
            if !next.is_ascii_digit() {
                break;
            }
            digits.push(next);
            chars.next();
        }
        if closed {
            if let Ok(index) = digits.parse::<usize>() {
                found.insert(index);
            }
        }
    }
    found
}

/// The shipped catalogue for `locale`, for tooling that wants one directly.
///
/// # Errors
///
/// [`Error::InvalidSettings`] if the shipped catalogue is malformed, or if
/// `locale` is not one this build ships.
pub fn shipped(locale: &str) -> Result<Catalog> {
    match locale {
        "en" => Catalog::parse("en", EN),
        "tr" => Catalog::parse("tr", TR),
        other => Err(Error::InvalidSettings(format!(
            "no catalogue for '{other}'; this build ships {}",
            SHIPPED_LOCALES.join(", ")
        ))),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn both_shipped_catalogues_parse() {
        for locale in SHIPPED_LOCALES {
            let catalog = shipped(locale).unwrap();
            assert!(!catalog.is_empty(), "{locale} is empty");
        }
    }

    #[test]
    fn the_turkish_catalogue_is_complete() {
        // The rule that keeps the fallback honest: a missing key is a build
        // failure here and a silent fallback for the user, which is the right
        // way round.
        let report = audit(&shipped("en").unwrap(), &shipped("tr").unwrap());
        assert!(report.is_clean(), "tr: {}", report.describe());
    }

    #[test]
    fn the_audit_catches_what_it_claims_to() {
        // A guard that never fails is a guard nobody should trust.
        let fallback = Catalog::parse("en", r#"{"a":"one {0}","b":"two","c":"three"}"#).unwrap();
        let translation = Catalog::parse("tr", r#"{"a":"bir","b":"  ","d":"dort"}"#).unwrap();
        let report = audit(&fallback, &translation);
        assert_eq!(report.missing, vec!["c"]);
        assert_eq!(report.extra, vec!["d"]);
        assert_eq!(report.placeholder_mismatch, vec!["a"]);
        assert_eq!(report.empty, vec!["b"]);
        assert!(!report.is_clean());
    }

    #[test]
    fn placeholders_substitute_positionally() {
        let messages = Messages::for_locale("en").unwrap();
        assert_eq!(
            interpolate("added {0} ({1})", &["Cinemeta", "8 catalogues"]),
            "added Cinemeta (8 catalogues)"
        );
        // Reordered, which is the whole reason indices are positional.
        assert_eq!(
            interpolate("{1} icin {0}", &["Cinemeta", "8 katalog"]),
            "8 katalog icin Cinemeta"
        );
        // The same index twice.
        assert_eq!(interpolate("{0}/{0}", &["x"]), "x/x");
        let _ = messages;
    }

    #[test]
    fn a_literal_brace_is_doubled() {
        assert_eq!(interpolate("{{0}}", &["x"]), "{0}");
        assert_eq!(interpolate("{{", &[]), "{");
        assert_eq!(interpolate("a {{b}} c", &[]), "a {b} c");
    }

    #[test]
    fn a_missing_argument_stays_visible() {
        // A bug report beats a sentence that reads fine and says something
        // false.
        assert_eq!(interpolate("x {0} y {1}", &["a"]), "x a y {1}");
    }

    #[test]
    fn text_that_is_not_a_placeholder_survives_untouched() {
        assert_eq!(interpolate("100% {sure}", &[]), "100% {sure}");
        assert_eq!(interpolate("a{b}c", &["z"]), "a{b}c");
        assert_eq!(interpolate("unclosed {0", &["z"]), "unclosed {0");
    }

    #[test]
    fn an_unknown_locale_yields_english_without_complaint() {
        let messages = Messages::for_locale("de-AT").unwrap();
        assert_eq!(messages.locale(), "en");
        // And a key that exists reads as English.
        assert!(!messages.get("cli.help.header").is_empty());
    }

    #[test]
    fn a_region_narrows_to_its_language() {
        let messages = Messages::for_locale("tr-TR").unwrap();
        assert_eq!(messages.locale(), "tr");
        assert!(messages.is_translated("cli.help.header"));
    }

    #[test]
    fn an_unknown_key_returns_itself() {
        let messages = Messages::for_locale("tr").unwrap();
        assert_eq!(messages.get("no.such.key"), "no.such.key");
    }

    #[test]
    fn a_nested_catalogue_is_refused_rather_than_flattened() {
        // So a key is always exactly what the code asks for.
        let err = Catalog::parse("en", r#"{"a":{"b":"c"}}"#).unwrap_err();
        assert!(err.to_string().contains("an object"), "{err}");
        assert!(Catalog::parse("en", r#"{"a":["b"]}"#).is_err());
        assert!(Catalog::parse("en", r#"{"a":null}"#).is_err());
        assert!(Catalog::parse("en", r#"{"a":3}"#).is_err());
    }

    #[test]
    fn every_key_the_library_names_exists() {
        // The enums carry message keys; this is what proves they resolve.
        use crate::{module::Permission, revocation::RevocationReason};
        let english = shipped("en").unwrap();
        for permission in [
            Permission::NetFetch,
            Permission::StorageLocal,
            Permission::FsReadUserSelected,
            Permission::FsWriteDownloads,
            Permission::PlayerControl,
            Permission::CatalogRead,
            Permission::AddonsRead,
            Permission::UiSurface,
            Permission::NotificationsPost,
            Permission::ClipboardWrite,
        ] {
            let key = permission.message_key();
            assert!(english.get(key).is_some(), "{key} is missing");
        }
        for reason in [
            RevocationReason::MaliciousCode,
            RevocationReason::KeyCompromise,
            RevocationReason::SecurityVulnerability,
            RevocationReason::LicenseViolation,
            RevocationReason::LegalOrder,
            RevocationReason::PublisherRequest,
        ] {
            let key = reason.message_key();
            assert!(english.get(key).is_some(), "{key} is missing");
        }
    }

    #[test]
    fn turkish_is_actually_turkish() {
        // A catalogue copied from English passes every structural check and is
        // not a translation. Spot-checking a handful of keys is crude and
        // catches exactly that.
        let english = shipped("en").unwrap();
        let turkish = shipped("tr").unwrap();
        let mut identical = 0;
        let mut compared = 0;
        for key in english.keys() {
            if let (Some(en), Some(tr)) = (english.get(key), turkish.get(key)) {
                // Messages that are only a placeholder, or a bare proper noun,
                // are legitimately the same in both.
                if en.chars().filter(char::is_ascii_alphabetic).count() < 4 {
                    continue;
                }
                compared += 1;
                if en == tr {
                    identical += 1;
                }
            }
        }
        assert!(compared > 20, "too few messages to judge: {compared}");
        let ratio = f64::from(identical) / f64::from(compared);
        assert!(
            ratio < 0.2,
            "{identical} of {compared} Turkish messages are identical to the English"
        );
    }
}
