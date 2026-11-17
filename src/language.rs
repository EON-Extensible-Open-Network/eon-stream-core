// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 EON contributors
//
// Additional permission under GNU GPL version 3 section 7:
// see LICENSE-EXCEPTION.md (EON Module ABI Exception 1.0).

//! Deciding whether two language labels mean the same language.
//!
//! This exists because prefix matching looked like it would do and does not.
//! `eng` starts with `en`, so that pair works by accident — and **`tur` does
//! not start with `tr`**, so the project's own first language was the one that
//! silently failed. A viewer asking for Turkish subtitles got "no match" from
//! an addon that was offering them.
//!
//! So there is a table. It is deliberately short: the languages this project
//! actually serves, plus the ones whose two- and three-letter codes differ
//! enough to break the naive comparison. Adding a language is adding a row,
//! and a language that is missing degrades to the prefix comparison rather
//! than to nothing.
//!
//! ## Why not a crate
//!
//! A full ISO 639 table is a few hundred rows and three registries deep
//! (639-1, 639-2/T, 639-2/B), and the part that matters here is matching, not
//! enumeration. What addons write is a handful of forms — `tr`, `tur`,
//! `Turkish`, `türkçe` — and this maps those.

use crate::fuzzy;

/// One language and the ways addons write it.
///
/// The first entry of each row is the canonical two-letter code; the rest are
/// aliases, including the English and native names, because addons write those
/// too.
///
/// Aliases are stored **already normalised** — `turkce`, not `türkçe`. A
/// lookup normalises its input before comparing, so an entry with diacritics
/// could never be matched and would be dead data that looked like coverage.
/// There is a test for it.
const ALIASES: &[&[&str]] = &[
    // The project's own languages first, and the pair that caused this file.
    &["tr", "tur", "turkish", "turkce"],
    &["en", "eng", "english", "ingilizce"],
    // Then the ones a viewer here is most likely to meet, and the ones whose
    // codes a prefix comparison gets wrong.
    &["de", "deu", "ger", "german", "almanca"],
    &["fr", "fra", "fre", "french", "fransizca"],
    &["es", "spa", "spanish", "espanol", "ispanyolca"],
    &["ar", "ara", "arabic", "arapca"],
    &["ru", "rus", "russian", "rusca"],
    &["fa", "fas", "per", "persian", "farsi", "farsca"],
    &["ku", "kur", "kurdish", "kurtce", "kurmanci"],
    &["az", "aze", "azerbaijani", "azerice"],
    &["el", "ell", "gre", "greek", "yunanca"],
    &["nl", "nld", "dut", "dutch", "flemish"],
    &["zh", "zho", "chi", "chinese", "mandarin"],
    &["ja", "jpn", "japanese", "japonca"],
    &["ko", "kor", "korean", "korece"],
    &["it", "ita", "italian", "italyanca"],
    &["pt", "por", "portuguese", "portekizce"],
    &["hi", "hin", "hindi"],
    &["he", "heb", "iw", "hebrew"],
    &["pl", "pol", "polish"],
    &["ro", "ron", "rum", "romanian"],
    &["bg", "bul", "bulgarian"],
    &["sr", "srp", "serbian"],
    &["hr", "hrv", "croatian"],
    &["uk", "ukr", "ukrainian"],
    &["sv", "swe", "swedish"],
    &["da", "dan", "danish"],
    &["fi", "fin", "finnish"],
    &["no", "nor", "nob", "norwegian"],
    &["cs", "ces", "cze", "czech"],
    &["hu", "hun", "hungarian"],
    &["id", "ind", "indonesian"],
    &["th", "tha", "thai"],
    &["vi", "vie", "vietnamese"],
];

/// Strip a label down to something comparable.
///
/// Folds diacritics and drops punctuation, so `Türkçe`, `turkce` and `TURKISH`
/// all reduce usefully. A region suffix goes too: an addon writing `pt-BR` is
/// offering Portuguese, and a viewer who asked for `pt` wants it.
#[must_use]
pub fn normalize(label: &str) -> String {
    let folded = fuzzy::normalize(label);
    // `pt-br`, `pt_br` and `pt br` all arrive here as `pt br`.
    folded.split(' ').next().unwrap_or(&folded).to_owned()
}

/// The canonical two-letter code for a label, when it is known.
#[must_use]
pub fn canonical(label: &str) -> Option<&'static str> {
    let wanted = normalize(label);
    if wanted.is_empty() {
        return None;
    }
    ALIASES
        .iter()
        .find_map(|row| row.iter().any(|alias| *alias == wanted).then(|| row[0]))
}

/// Every language the table knows, by canonical two-letter code, in table
/// order.
///
/// This is what a picker offers. A viewer choosing from a list cannot type a
/// language nobody will ever match, which a free-text box let them do -- and
/// each code here has a name in the interface catalogue (`ui.lang.<code>`),
/// which a test in `i18n` holds to.
pub fn known() -> impl Iterator<Item = &'static str> {
    ALIASES.iter().map(|row| row[0])
}

/// Whether two labels name the same language.
///
/// Known languages are compared through the table; anything the table does not
/// carry falls back to a prefix comparison, which is right more often than it
/// is wrong for codes nobody here has written a row for.
#[must_use]
pub fn matches(a: &str, b: &str) -> bool {
    let (left, right) = (normalize(a), normalize(b));
    if left.is_empty() || right.is_empty() {
        return false;
    }
    if left == right {
        return true;
    }
    match (canonical(&left), canonical(&right)) {
        // Both known: the table is the whole answer, and a disagreement here
        // is a real disagreement rather than a spelling difference.
        (Some(x), Some(y)) => x == y,
        // One or neither known: fall back rather than refuse, since the table
        // is short on purpose.
        _ => left.starts_with(&right) || right.starts_with(&left),
    }
}

/// Whether a label matches any of the languages asked for.
#[must_use]
pub fn matches_any(label: &str, wanted: &[String]) -> bool {
    wanted.iter().any(|one| matches(label, one))
}

/// Where a label falls in a preference list, lower being more wanted.
///
/// `None` when it matches nothing, so a caller can sort unmatched languages
/// after every matched one instead of treating them as the first preference.
#[must_use]
pub fn preference_rank(label: &str, wanted: &[String]) -> Option<usize> {
    wanted.iter().position(|one| matches(label, one))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn the_pair_that_caused_this_file() {
        // `tur` does not start with `tr`, so prefix matching failed for the
        // project's own first language. That is the bug this fixes.
        assert!(matches("tr", "tur"));
        assert!(matches("tur", "tr"));
        assert!(
            !"tur".starts_with("tr"),
            "the naive comparison really does fail"
        );
    }

    #[test]
    fn the_pair_that_worked_by_accident_still_works() {
        // `eng` does start with `en`, which is why this was never noticed.
        assert!(matches("en", "eng"));
        assert!(matches("eng", "en"));
    }

    #[test]
    fn names_and_native_spellings_match_their_codes() {
        assert!(matches("Turkish", "tr"));
        assert!(matches("Türkçe", "tur"));
        assert!(matches("türkçe", "turkish"));
        assert!(matches("English", "eng"));
        assert!(matches("Almanca", "de"));
    }

    #[test]
    fn the_three_letter_variants_addons_actually_send() {
        // 639-2/B and 639-2/T disagree for several languages, and addons send
        // both.
        assert!(matches("ger", "de"));
        assert!(matches("deu", "ger"));
        assert!(matches("fre", "fra"));
        assert!(matches("gre", "ell"));
        assert!(matches("dut", "nld"));
        assert!(matches("per", "fas"));
        assert!(matches("chi", "zho"));
        assert!(matches("rum", "ron"));
        assert!(matches("cze", "ces"));
    }

    #[test]
    fn a_region_suffix_does_not_prevent_a_match() {
        // An addon writing pt-BR is offering Portuguese.
        assert!(matches("pt-BR", "pt"));
        assert!(matches("pt_BR", "por"));
        assert!(matches("en-US", "eng"));
        assert!(matches("tr-TR", "tur"));
    }

    #[test]
    fn different_languages_do_not_match() {
        // The table has to separate as well as join.
        assert!(!matches("tr", "en"));
        assert!(!matches("de", "nl"));
        assert!(
            !matches("fa", "ar"),
            "Persian and Arabic are not the same language"
        );
        assert!(!matches("ku", "tr"), "nor are Kurdish and Turkish");
        assert!(!matches("sr", "hr"));
    }

    #[test]
    fn an_unknown_code_falls_back_rather_than_refusing() {
        // The table is short on purpose; a language nobody wrote a row for
        // should still behave sensibly.
        assert!(matches("xyz", "xyz"));
        assert!(matches("xy", "xyz"));
        assert!(!matches("xyz", "abc"));
        assert!(canonical("xyz").is_none());
    }

    #[test]
    fn empty_labels_match_nothing() {
        assert!(!matches("", "tr"));
        assert!(!matches("tr", ""));
        assert!(!matches("", ""));
        assert!(!matches("!!!", "tr"));
        assert!(canonical("").is_none());
    }

    #[test]
    fn canonical_codes_are_the_two_letter_form() {
        assert_eq!(canonical("Turkish"), Some("tr"));
        assert_eq!(canonical("tur"), Some("tr"));
        assert_eq!(canonical("ger"), Some("de"));
        assert_eq!(canonical("pt-BR"), Some("pt"));
    }

    #[test]
    fn matching_against_a_preference_list() {
        let wanted = vec!["tur".to_owned(), "eng".to_owned()];
        assert!(matches_any("tr", &wanted));
        assert!(matches_any("English", &wanted));
        assert!(!matches_any("de", &wanted));

        // Order is the preference, so Turkish outranks English here.
        assert_eq!(preference_rank("tr", &wanted), Some(0));
        assert_eq!(preference_rank("en", &wanted), Some(1));
        // Unmatched is None rather than a large number, so a caller can sort
        // it after everything matched instead of treating it as first choice.
        assert_eq!(preference_rank("de", &wanted), None);
    }

    #[test]
    fn no_alias_appears_in_two_rows() {
        // One alias meaning two languages would make matching ambiguous and
        // the table silently wrong.
        let mut seen: Vec<&str> = ALIASES.iter().flat_map(|row| row.iter().copied()).collect();
        let before = seen.len();
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(seen.len(), before, "an alias is listed under two languages");
    }

    #[test]
    fn every_row_is_normalised_already() {
        // An alias that does not survive normalisation can never be matched,
        // which would be dead data that looks like coverage.
        for row in ALIASES {
            for alias in *row {
                assert_eq!(
                    normalize(alias),
                    *alias,
                    "{alias} is not in normalised form, so it can never match"
                );
            }
        }
    }
}
