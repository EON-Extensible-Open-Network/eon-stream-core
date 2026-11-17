// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 EON contributors
//
// Additional permission under GNU GPL version 3 section 7:
// see LICENSE-EXCEPTION.md (EON Module ABI Exception 1.0).

//! Approximate string matching, for search that survives a typo.
//!
//! The behaviour this exists for: someone types `befer coll saol`, and instead
//! of "no results" they get *Better Call Saul*, told plainly that a correction
//! happened and offered the literal query back.
//!
//! ## Why this is not a spell checker
//!
//! There is no dictionary here and there should not be. A film called
//! *Inglourious Basterds* is spelled wrong on purpose, and a dictionary would
//! "fix" it. So corrections are only ever made **towards titles that actually
//! exist** — names an addon returned, items in the library, things already
//! watched. The candidate list is the vocabulary, which means this can never
//! invent a title and can never correct a correct one into something else.
//!
//! ## Turkish folding is not an optional nicety
//!
//! This project is Turkish-first (madde 40), and Turkish keyboards are not
//! always what someone is typing on. `guzel` must match `Güzel`, `cilgin` must
//! match `Çılgın`. Folding the diacritics is therefore part of normalisation
//! rather than a later refinement — and it has to fold the dotless `ı` and the
//! dotted `İ` together with `i`, which is the one case a naive
//! `to_lowercase()` gets wrong in the other direction.
//!
//! ## Two measures, because one is not enough
//!
//! Edit distance over the whole string handles `saol` → `saul`. It handles
//! word order and missing words badly: `saul better call` is the same film, and
//! whole-string distance says it is barely related. So the score is the better
//! of a whole-string measure and a token measure, which between them cover the
//! mistakes people actually make.

/// How similar two strings must be before a correction is offered.
///
/// Tuned against the cases in the tests rather than chosen roundly. Lower and
/// `the matrix` starts suggesting `the mist`; higher and `befer coll saol`
/// stops reaching `better call saul`, which is the case this was built for.
pub const MIN_SIMILARITY: f64 = 0.62;

/// Fold a character towards its unaccented ASCII form.
///
/// Turkish first, because that is this project's first language, then the
/// Latin-1 letters a European title is likely to carry. Anything else is left
/// alone: folding an alphabet nobody here can check would silently break
/// search for its speakers.
fn fold(ch: char) -> Option<char> {
    Some(match ch {
        // Turkish. `ı` and `İ` both fold to `i`, which is the pair a
        // locale-unaware `to_lowercase` cannot get right in both directions.
        'ı' | 'İ' | 'î' | 'ï' | 'í' | 'ì' => 'i',
        'ş' | 'Ş' => 's',
        'ğ' | 'Ğ' => 'g',
        'ü' | 'Ü' | 'û' | 'ù' | 'ú' => 'u',
        'ö' | 'Ö' | 'ô' | 'ò' | 'ó' | 'õ' => 'o',
        'ç' | 'Ç' => 'c',
        // Latin-1 and friends.
        'á' | 'à' | 'â' | 'ä' | 'ã' | 'å' => 'a',
        'é' | 'è' | 'ê' | 'ë' => 'e',
        'ñ' => 'n',
        'ý' | 'ÿ' => 'y',
        'æ' => 'a',
        'ø' => 'o',
        'ß' => 's',
        _ => return None,
    })
}

/// Lowercase, fold diacritics, drop punctuation, collapse whitespace.
///
/// Punctuation goes because titles disagree about it — `Spider-Man`,
/// `Spider Man`, `SpiderMan` — and a viewer typing one should find the others.
#[must_use]
pub fn normalize(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut last_was_space = true;
    for raw in text.chars() {
        let folded = fold(raw).unwrap_or(raw);
        // `flat_map` over `to_lowercase` because one character can lower to
        // several, and dropping the extras would corrupt the comparison.
        for ch in folded.to_lowercase() {
            if ch.is_alphanumeric() {
                out.push(ch);
                last_was_space = false;
            } else if !last_was_space {
                out.push(' ');
                last_was_space = true;
            }
        }
    }
    if out.ends_with(' ') {
        out.pop();
    }
    out
}

/// Optimal string alignment distance: insertions, deletions, substitutions and
/// transpositions of adjacent characters.
///
/// Transpositions matter here specifically. `saul` typed as `saul` with the
/// vowels swapped, `the` as `teh`, `form` as `from` — those are one mistake to
/// a person and two to plain Levenshtein, which is enough to push a real match
/// under the threshold.
#[must_use]
pub fn distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    if a.is_empty() {
        return b.len();
    }
    if b.is_empty() {
        return a.len();
    }

    // Three rows are enough for optimal string alignment: the transposition
    // rule only ever looks two back. A full matrix would be clearer and would
    // also allocate len(a) * len(b) for strings that can be a whole catalogue
    // of titles.
    let mut two_back: Vec<usize> = vec![0; b.len() + 1];
    let mut one_back: Vec<usize> = (0..=b.len()).collect();
    let mut current: Vec<usize> = vec![0; b.len() + 1];

    for (i, &ach) in a.iter().enumerate() {
        current[0] = i + 1;
        for (j, &bch) in b.iter().enumerate() {
            let cost = usize::from(ach != bch);
            let mut best = (one_back[j] + cost)
                .min(current[j] + 1)
                .min(one_back[j + 1] + 1);
            if i > 0 && j > 0 && ach == b[j - 1] && a[i - 1] == bch {
                best = best.min(two_back[j - 1] + 1);
            }
            current[j + 1] = best;
        }
        std::mem::swap(&mut two_back, &mut one_back);
        std::mem::swap(&mut one_back, &mut current);
    }
    one_back[b.len()]
}

/// Edit distance expressed as a 0.0–1.0 similarity.
fn ratio(a: &str, b: &str) -> f64 {
    let longest = a.chars().count().max(b.chars().count());
    if longest == 0 {
        return 1.0;
    }
    #[allow(clippy::cast_precision_loss)]
    let scaled = distance(a, b) as f64 / longest as f64;
    (1.0 - scaled).clamp(0.0, 1.0)
}

/// Similarity that tolerates reordered and missing words.
///
/// Every query token is matched against its best candidate token, and the
/// result is weighted by token length so a wrong short word costs less than a
/// wrong long one. `saul better call` scores high against `better call saul`;
/// `better` alone scores lower, because most of the title is missing.
fn token_ratio(query: &str, candidate: &str) -> f64 {
    let query_tokens: Vec<&str> = query.split(' ').filter(|t| !t.is_empty()).collect();
    let candidate_tokens: Vec<&str> = candidate.split(' ').filter(|t| !t.is_empty()).collect();
    if query_tokens.is_empty() || candidate_tokens.is_empty() {
        return 0.0;
    }

    let mut weighted = 0.0;
    let mut weight_total = 0.0;
    for token in &query_tokens {
        let best = candidate_tokens
            .iter()
            .map(|other| ratio(token, other))
            .fold(0.0_f64, f64::max);
        #[allow(clippy::cast_precision_loss)]
        let weight = token.chars().count() as f64;
        weighted += best * weight;
        weight_total += weight;
    }
    let matched = if weight_total > 0.0 {
        weighted / weight_total
    } else {
        0.0
    };

    // A query that covers only part of the candidate is penalised in
    // proportion to what it leaves out, so `better` does not score as highly
    // against `better call saul` as `better call saul` does.
    #[allow(clippy::cast_precision_loss)]
    let coverage = (query_tokens.len() as f64 / candidate_tokens.len() as f64).min(1.0);
    matched * (0.55 + 0.45 * coverage)
}

/// How alike two strings are, after normalisation, between 0.0 and 1.0.
///
/// The better of a whole-string and a token measure: the first catches typos,
/// the second catches reordering and omission, and a real match usually scores
/// well on one of them rather than both.
#[must_use]
pub fn similarity(query: &str, candidate: &str) -> f64 {
    let query = normalize(query);
    let candidate = normalize(candidate);
    if query.is_empty() || candidate.is_empty() {
        return 0.0;
    }
    if query == candidate {
        return 1.0;
    }
    // A query that is a leading fragment of the candidate is someone typing
    // the start of a title, not making a mistake.
    if candidate.starts_with(&query) && query.chars().count() >= 3 {
        #[allow(clippy::cast_precision_loss)]
        let covered = query.chars().count() as f64 / candidate.chars().count() as f64;
        return (0.80 + 0.20 * covered).min(1.0);
    }
    ratio(&query, &candidate).max(token_ratio(&query, &candidate))
}

/// A correction worth offering.
#[derive(Debug, Clone, PartialEq)]
pub struct Suggestion {
    /// The candidate the query was corrected to.
    pub corrected: String,
    /// What the viewer actually typed, kept so it can be offered back.
    pub original: String,
    /// How alike the two are, 0.0–1.0.
    pub score: f64,
}

impl Suggestion {
    /// Whether the correction changed anything a person would notice.
    ///
    /// A query differing from the candidate only in case, punctuation or
    /// diacritics is not a correction worth announcing — nobody wants to be
    /// told their search for `spider man` was corrected to `Spider-Man`.
    #[must_use]
    pub fn is_meaningful(&self) -> bool {
        normalize(&self.original) != normalize(&self.corrected)
    }
}

/// The closest candidate to `query`, if any is close enough.
///
/// Returns `None` rather than the least-bad option: offering a correction
/// nobody would recognise is worse than admitting nothing was found.
#[must_use]
pub fn suggest(query: &str, candidates: &[&str]) -> Option<Suggestion> {
    suggest_above(query, candidates, MIN_SIMILARITY)
}

/// [`suggest`] with an explicit threshold, for callers that know their
/// candidate list is trustworthy enough to relax it.
#[must_use]
pub fn suggest_above(query: &str, candidates: &[&str], minimum: f64) -> Option<Suggestion> {
    let mut best: Option<Suggestion> = None;
    for candidate in candidates {
        let score = similarity(query, candidate);
        if score < minimum {
            continue;
        }
        let better = best.as_ref().is_none_or(|current| {
            // Ties go to the shorter title: between `Saul` and `Better Call
            // Saul` for a query that matches both, the tighter match is the
            // one a person meant.
            score > current.score
                || (score == current.score
                    && candidate.chars().count() < current.corrected.chars().count())
        });
        if better {
            best = Some(Suggestion {
                corrected: (*candidate).to_owned(),
                original: query.to_owned(),
                score,
            });
        }
    }
    best
}

/// Order candidates by how well they match, best first, dropping the ones that
/// do not match at all.
///
/// Used for ranking search results rather than for correcting a query, so the
/// threshold is deliberately loose: a weak match is still worth showing below
/// the strong ones, where "no results" would not be.
#[must_use]
pub fn rank_matches<'a>(query: &str, candidates: &[&'a str]) -> Vec<(&'a str, f64)> {
    let mut scored: Vec<(&'a str, f64)> = candidates
        .iter()
        .map(|candidate| (*candidate, similarity(query, candidate)))
        .filter(|(_, score)| *score > 0.30)
        .collect();
    scored.sort_by(|a, b| {
        b.1.partial_cmp(&a.1)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.0.chars().count().cmp(&b.0.chars().count()))
    });
    scored
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn the_case_this_was_built_for() {
        // Typed by a person, from the report that prompted this module.
        let candidates = ["Better Call Saul", "Breaking Bad", "The Sopranos"];
        let suggestion = suggest("befer coll saol", &candidates).expect("a correction");
        assert_eq!(suggestion.corrected, "Better Call Saul");
        assert_eq!(suggestion.original, "befer coll saol");
        assert!(suggestion.is_meaningful());
    }

    #[test]
    fn normalisation_folds_turkish() {
        // A Turkish keyboard is not always what someone is typing on.
        assert_eq!(normalize("Güzel Çılgın Şarkı"), "guzel cilgin sarki");
        assert_eq!(normalize("IŞIK"), "isik");
        assert_eq!(normalize("ılık"), "ilik");
        // Both spellings of the letter i reach the same place, which is the
        // pair a locale-unaware lowercase cannot do in both directions.
        assert_eq!(normalize("İstanbul"), normalize("istanbul"));
        assert_eq!(normalize("ISTANBUL"), normalize("ıstanbul"));
    }

    #[test]
    fn a_turkish_title_is_found_without_its_diacritics() {
        let candidates = ["Çılgın Hırsız", "Güzel Bir Gün"];
        let found = suggest("cilgin hirsiz", &candidates).expect("a match");
        assert_eq!(found.corrected, "Çılgın Hırsız");
        // Nothing a person would call a correction: same word, plainer letters.
        assert!(!found.is_meaningful());
    }

    #[test]
    fn normalisation_ignores_punctuation_and_case() {
        assert_eq!(
            normalize("Spider-Man: No Way Home"),
            "spider man no way home"
        );
        assert_eq!(normalize("  WALL·E  "), "wall e");
        assert_eq!(normalize("Am\u{e9}lie"), "amelie");
        assert_eq!(normalize("!!!"), "");
    }

    #[test]
    fn transpositions_count_as_one_mistake() {
        // Plain Levenshtein charges two for a swap, which is enough to push a
        // real match under the threshold.
        assert_eq!(distance("saul", "saul"), 0);
        // One swap of adjacent characters is one mistake, not two.
        assert_eq!(distance("saul", "sual"), 1);
        assert_eq!(distance("teh", "the"), 1);
        // And the case from the report: a single wrong vowel.
        assert_eq!(distance("saol", "saul"), 1);
        assert_eq!(distance("coll", "call"), 1);
        assert_eq!(distance("from", "form"), 1);
        assert_eq!(distance("", "abc"), 3);
        assert_eq!(distance("abc", ""), 3);
    }

    #[test]
    fn reordered_words_still_match() {
        // Whole-string distance says these are barely related; a person says
        // they are the same film.
        assert!(similarity("saul better call", "Better Call Saul") > MIN_SIMILARITY);
        assert!(similarity("bad breaking", "Breaking Bad") > MIN_SIMILARITY);
    }

    #[test]
    fn typing_the_start_of_a_title_is_not_a_typo() {
        assert!(similarity("better", "Better Call Saul") > MIN_SIMILARITY);
        assert!(similarity("breaking", "Breaking Bad") > MIN_SIMILARITY);
        // And is scored as a prefix rather than as a bad edit distance.
        assert!(similarity("the matr", "The Matrix") > 0.8);
    }

    #[test]
    fn a_deliberate_misspelling_is_not_corrected_away() {
        // The reason there is no dictionary here. `Inglourious Basterds` is
        // spelled wrong on purpose, and a speller would ruin it.
        let candidates = ["Inglourious Basterds"];
        let found = suggest("Inglourious Basterds", &candidates).expect("itself");
        assert_eq!(found.corrected, "Inglourious Basterds");
        assert!(!found.is_meaningful(), "an exact title is not a correction");
    }

    #[test]
    fn nothing_close_enough_suggests_nothing() {
        // Offering a correction nobody would recognise is worse than admitting
        // nothing was found.
        let candidates = ["Better Call Saul", "Breaking Bad"];
        assert!(suggest("the godfather", &candidates).is_none());
        assert!(suggest("zzzzzzzz", &candidates).is_none());
        assert!(suggest("", &candidates).is_none());
        assert!(suggest("anything", &[]).is_none());
    }

    #[test]
    fn similar_titles_do_not_bleed_into_each_other() {
        // The threshold exists for this: these are different films and a search
        // for one must not be corrected to the other.
        let candidates = ["The Mist", "The Matrix"];
        let found = suggest("the matrix", &candidates).expect("a match");
        assert_eq!(found.corrected, "The Matrix");
        assert!(similarity("the matrix", "The Mist") < MIN_SIMILARITY);
    }

    #[test]
    fn a_tie_goes_to_the_tighter_title() {
        // Between `Saul` and `Better Call Saul` for a query matching both, the
        // shorter one is what a person meant.
        let candidates = ["Better Call Saul", "Saul"];
        let found = suggest("saul", &candidates).expect("a match");
        assert_eq!(found.corrected, "Saul");
    }

    #[test]
    fn ranking_orders_by_closeness_and_keeps_weak_matches() {
        let candidates = ["Better Call Saul", "Breaking Bad", "Better Things"];
        let ranked = rank_matches("better call", &candidates);
        assert_eq!(
            ranked.first().map(|(name, _)| *name),
            Some("Better Call Saul")
        );
        // A weak match is still worth showing below the strong ones, where
        // "no results" would not be.
        assert!(ranked.len() >= 2, "{ranked:?}");
        // Scores descend.
        for pair in ranked.windows(2) {
            assert!(pair[0].1 >= pair[1].1);
        }
    }

    #[test]
    fn ranking_drops_what_is_unrelated() {
        let candidates = ["Better Call Saul", "The Godfather"];
        let ranked = rank_matches("better call saul", &candidates);
        assert!(
            ranked.iter().all(|(name, _)| *name != "The Godfather"),
            "{ranked:?}"
        );
    }

    #[test]
    fn similarity_is_symmetric_enough_to_be_predictable() {
        // Not required to be exactly symmetric -- coverage is directional --
        // but a query and a candidate swapping places must not flip a match
        // into a non-match.
        for (a, b) in [
            ("better call saul", "Better Call Saul"),
            ("teh matrix", "The Matrix"),
        ] {
            assert!(similarity(a, b) > MIN_SIMILARITY);
            assert!(similarity(b, a) > MIN_SIMILARITY);
        }
    }

    #[test]
    fn long_queries_do_not_blow_up() {
        // The row-based distance exists so a catalogue of titles does not
        // allocate a matrix per comparison.
        let long = "a".repeat(2000);
        let other = "b".repeat(2000);
        assert_eq!(distance(&long, &other), 2000);
        assert!(similarity(&long, &other) < 0.1);
    }

    #[test]
    fn a_meaningful_correction_is_distinguished_from_a_cosmetic_one() {
        let cosmetic = Suggestion {
            corrected: "Spider-Man".to_owned(),
            original: "spider man".to_owned(),
            score: 1.0,
        };
        assert!(!cosmetic.is_meaningful());

        let real = Suggestion {
            corrected: "Better Call Saul".to_owned(),
            original: "befer coll saol".to_owned(),
            score: 0.7,
        };
        assert!(real.is_meaningful());
    }
}
