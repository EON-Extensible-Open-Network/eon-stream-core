// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 EON contributors
//
// Additional permission under GNU GPL version 3 section 7:
// see LICENSE-EXCEPTION.md (EON Module ABI Exception 1.0).

//! Versions and version ranges.
//!
//! Written here rather than taken from a crate because the contract asks for
//! **npm range syntax** (`^1.2.0`, `>=0.3 <1.0`) — that is what
//! `schemas/module-manifest.v0.schema.json` says a dependency carries, and it
//! is what an addon author will type. The `semver` crate parses *Cargo*
//! syntax, which overlaps enough to be dangerous: `^0.2.3` means
//! `>=0.2.3 <0.3.0` in both, but a bare `1.2` means `^1.2` to Cargo and
//! `=1.2.x` to npm. Resolving a dependency differently from the published
//! contract is the kind of bug nobody finds for a year.
//!
//! The subset implemented is the subset the contract allows: comparators
//! (`=`, `>`, `>=`, `<`, `<=`), caret, tilde, wildcards, and partial versions.
//! Hyphen ranges (`1.2 - 1.5`) and `||` alternation are **rejected rather than
//! misparsed** — refusing loudly beats resolving to something the author did
//! not write.

use std::{cmp::Ordering, fmt};

use crate::error::{Error, Result};

/// A semantic version.
///
/// Build metadata (`+sha.1234`) is accepted and then discarded: semver says it
/// is not part of precedence, and keeping it would invite comparing on it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Version {
    /// Major version.
    pub major: u64,
    /// Minor version.
    pub minor: u64,
    /// Patch version.
    pub patch: u64,
    /// Pre-release identifiers, already split on `.`. Empty for a release.
    pub pre: Vec<String>,
}

impl Version {
    /// A release version with no pre-release part.
    #[must_use]
    pub const fn new(major: u64, minor: u64, patch: u64) -> Self {
        Self {
            major,
            minor,
            patch,
            pre: Vec::new(),
        }
    }

    /// Parse a full `major.minor.patch[-pre][+build]`.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidVersion`] if any component is missing, non-numeric, or
    /// carries a leading zero. Leading zeros are rejected because `01.0.0` and
    /// `1.0.0` would otherwise be two spellings of one version, and signatures
    /// bind to the spelling.
    pub fn parse(text: &str) -> Result<Self> {
        let text = text.trim();
        if text.is_empty() {
            return Err(Error::InvalidVersion("empty version".to_owned()));
        }
        // Build metadata is not part of precedence; drop it after checking it
        // is not empty, since `1.0.0+` is malformed rather than harmless.
        let (core_and_pre, build) = match text.split_once('+') {
            Some((head, build)) => (head, Some(build)),
            None => (text, None),
        };
        if build.is_some_and(str::is_empty) {
            return Err(Error::InvalidVersion(format!(
                "{text}: build metadata is empty"
            )));
        }

        let (core, pre) = match core_and_pre.split_once('-') {
            Some((core, pre)) => (core, Some(pre)),
            None => (core_and_pre, None),
        };

        let mut parts = core.split('.');
        let major = numeric_part(parts.next(), text)?;
        let minor = numeric_part(parts.next(), text)?;
        let patch = numeric_part(parts.next(), text)?;
        if parts.next().is_some() {
            return Err(Error::InvalidVersion(format!(
                "{text}: more than three numeric components"
            )));
        }

        let pre = match pre {
            None => Vec::new(),
            Some(pre) => {
                let ids: Vec<String> = pre.split('.').map(ToOwned::to_owned).collect();
                if ids.iter().any(|id| {
                    id.is_empty() || !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
                }) {
                    return Err(Error::InvalidVersion(format!(
                        "{text}: malformed pre-release identifier"
                    )));
                }
                ids
            }
        };

        Ok(Self {
            major,
            minor,
            patch,
            pre,
        })
    }

    /// Whether this is a pre-release.
    #[must_use]
    pub fn is_prerelease(&self) -> bool {
        !self.pre.is_empty()
    }

    /// The `(major, minor, patch)` triple, for comparisons that ignore the
    /// pre-release part.
    const fn core(&self) -> (u64, u64, u64) {
        (self.major, self.minor, self.patch)
    }
}

fn numeric_part(part: Option<&str>, whole: &str) -> Result<u64> {
    let part =
        part.ok_or_else(|| Error::InvalidVersion(format!("{whole}: expected major.minor.patch")))?;
    if part.is_empty() {
        return Err(Error::InvalidVersion(format!(
            "{whole}: empty numeric component"
        )));
    }
    if part.len() > 1 && part.starts_with('0') {
        return Err(Error::InvalidVersion(format!(
            "{whole}: leading zero in '{part}'"
        )));
    }
    part.parse::<u64>()
        .map_err(|_| Error::InvalidVersion(format!("{whole}: '{part}' is not a number")))
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)?;
        if !self.pre.is_empty() {
            write!(f, "-{}", self.pre.join("."))?;
        }
        Ok(())
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        self.core().cmp(&other.core()).then_with(|| {
            // A pre-release precedes its release: 1.0.0-rc < 1.0.0.
            match (self.pre.is_empty(), other.pre.is_empty()) {
                (true, true) => Ordering::Equal,
                (true, false) => Ordering::Greater,
                (false, true) => Ordering::Less,
                (false, false) => compare_prerelease(&self.pre, &other.pre),
            }
        })
    }
}

/// Pre-release precedence, semver §11.4: numeric identifiers compare
/// numerically and rank below alphanumeric ones; a shorter set of identifiers
/// precedes a longer one with the same prefix.
fn compare_prerelease(a: &[String], b: &[String]) -> Ordering {
    for (x, y) in a.iter().zip(b.iter()) {
        let ord = match (x.parse::<u64>(), y.parse::<u64>()) {
            (Ok(x), Ok(y)) => x.cmp(&y),
            (Ok(_), Err(_)) => Ordering::Less,
            (Err(_), Ok(_)) => Ordering::Greater,
            (Err(_), Err(_)) => x.cmp(y),
        };
        if ord != Ordering::Equal {
            return ord;
        }
    }
    a.len().cmp(&b.len())
}

/// How a comparator bounds a version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    Exact,
    Greater,
    GreaterEq,
    Less,
    LessEq,
}

#[derive(Debug, Clone)]
struct Comparator {
    op: Op,
    version: Version,
}

impl Comparator {
    fn allows(&self, candidate: &Version) -> bool {
        let ord = candidate.cmp(&self.version);
        match self.op {
            Op::Exact => ord == Ordering::Equal,
            Op::Greater => ord == Ordering::Greater,
            Op::GreaterEq => ord != Ordering::Less,
            Op::Less => ord == Ordering::Less,
            Op::LessEq => ord != Ordering::Greater,
        }
    }
}

impl fmt::Display for Comparator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let op = match self.op {
            Op::Exact => "=",
            Op::Greater => ">",
            Op::GreaterEq => ">=",
            Op::Less => "<",
            Op::LessEq => "<=",
        };
        write!(f, "{op}{}", self.version)
    }
}

/// A set of comparators that a version must satisfy **all** of.
///
/// `*` and the empty range accept anything.
#[derive(Debug, Clone, Default)]
pub struct VersionRange {
    comparators: Vec<Comparator>,
    source: String,
}

impl VersionRange {
    /// Accepts any version.
    #[must_use]
    pub fn any() -> Self {
        Self {
            comparators: Vec::new(),
            source: "*".to_owned(),
        }
    }

    /// Parse an npm-syntax range.
    ///
    /// Supported: `*`, `1.2.3`, `1.2`, `1`, `=1.2.3`, `>1.2.3`, `>=1.2.3`,
    /// `<2`, `<=1.2`, `^1.2.3`, `~1.2`, and whitespace-separated conjunctions
    /// of those.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidVersionRange`] for anything else — notably `||`
    /// alternation and `1.2 - 1.5` hyphen ranges, which this subset does not
    /// implement and will not guess at.
    pub fn parse(text: &str) -> Result<Self> {
        let source = text.trim().to_owned();
        if source.is_empty() || source == "*" || source == "x" || source == "X" {
            return Ok(Self {
                comparators: Vec::new(),
                source: if source.is_empty() {
                    "*".to_owned()
                } else {
                    source
                },
            });
        }
        if source.contains("||") {
            return Err(Error::InvalidVersionRange(format!(
                "{source}: alternation (||) is not supported"
            )));
        }
        // A hyphen range is `1.2 - 1.5`: a hyphen surrounded by whitespace. A
        // hyphen inside a pre-release tag (`1.0.0-rc.1`) is not one.
        if source.split_whitespace().any(|t| t == "-") {
            return Err(Error::InvalidVersionRange(format!(
                "{source}: hyphen ranges are not supported, write '>=1.2.0 <1.6.0'"
            )));
        }

        let mut comparators = Vec::new();
        for token in source.split_whitespace() {
            comparators.extend(parse_token(token, &source)?);
        }
        if comparators.is_empty() {
            return Err(Error::InvalidVersionRange(format!("{source}: empty range")));
        }
        Ok(Self {
            comparators,
            source,
        })
    }

    /// Whether `candidate` satisfies every comparator.
    ///
    /// Pre-releases follow the npm rule: `1.0.0-rc.1` satisfies `^1.0.0-rc.0`
    /// but **not** `^1.0.0`. Without that rule a caret range quietly opts an
    /// installation into untested pre-release builds.
    #[must_use]
    pub fn matches(&self, candidate: &Version) -> bool {
        if candidate.is_prerelease()
            && !self
                .comparators
                .iter()
                .any(|c| c.version.is_prerelease() && c.version.core() == candidate.core())
        {
            return false;
        }
        self.comparators.iter().all(|c| c.allows(candidate))
    }

    /// Whether `candidate` satisfies every comparator, **counting
    /// pre-releases**.
    ///
    /// The same arithmetic as [`matches`](Self::matches) without the npm
    /// pre-release opt-in rule, and the difference is deliberate rather than
    /// an oversight.
    ///
    /// For *installing* a dependency, excluding pre-releases is right: an
    /// unasked-for release candidate is a surprise, and the cost of being
    /// wrong is a dependency that does not resolve.
    ///
    /// For *revoking* a version it is exactly backwards. A revocation of
    /// `>=1.0.0 <1.5.0` is a statement that everything in that window is
    /// dangerous, and `1.4.2-rc.1` is in that window. Applying the install
    /// rule here would quietly leave pre-release builds of a revoked module
    /// enabled — and the cost of being wrong is a known-malicious module that
    /// stays running. When the two rules disagree, each side errs towards the
    /// cheaper mistake.
    ///
    /// Within that, the comparators keep plain semver ordering, so the two
    /// window edges behave asymmetrically and a publisher should know which:
    /// `1.5.0-rc.1` **is** below `<1.5.0` and so is covered, while
    /// `1.0.0-alpha` is below `1.0.0` and so is *not* covered by `>=1.0.0`.
    /// Both readings are literal; the practical consequence is that a
    /// revocation meaning "everything before the fix" should be written as the
    /// upper bound alone (`<1.5.0`), not as a two-sided window.
    #[must_use]
    pub fn matches_including_prereleases(&self, candidate: &Version) -> bool {
        self.comparators.iter().all(|c| c.allows(candidate))
    }

    /// The range exactly as it was written, for error messages that quote the
    /// author rather than this crate's reformatting of them.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.source
    }
}

impl fmt::Display for VersionRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.source)
    }
}

/// A version written with fewer than three components, as ranges allow.
struct Partial {
    major: u64,
    minor: Option<u64>,
    patch: Option<u64>,
    pre: Vec<String>,
}

impl Partial {
    fn lower(&self) -> Version {
        Version {
            major: self.major,
            minor: self.minor.unwrap_or(0),
            patch: self.patch.unwrap_or(0),
            pre: self.pre.clone(),
        }
    }
}

fn parse_partial(text: &str, whole: &str) -> Result<Partial> {
    let bad = || Error::InvalidVersionRange(format!("{whole}: '{text}' is not a version"));
    let (core_and_pre, _build) = match text.split_once('+') {
        Some((head, build)) => (head, Some(build)),
        None => (text, None),
    };
    let (core, pre) = match core_and_pre.split_once('-') {
        Some((core, pre)) => (core, Some(pre)),
        None => (core_and_pre, None),
    };

    let mut parts = core.split('.');
    let major = parts.next().ok_or_else(bad)?;
    let major = numeric_part(Some(major), whole)
        .map_err(|_| Error::InvalidVersionRange(format!("{whole}: '{text}' is not a version")))?;
    let mut minor = None;
    let mut patch = None;
    if let Some(part) = parts.next() {
        if !matches!(part, "x" | "X" | "*") {
            minor = Some(numeric_part(Some(part), whole).map_err(|_| bad())?);
        }
    }
    if let Some(part) = parts.next() {
        if !matches!(part, "x" | "X" | "*") {
            patch = Some(numeric_part(Some(part), whole).map_err(|_| bad())?);
        }
    }
    if parts.next().is_some() {
        return Err(bad());
    }
    // A pre-release tag on a partial version is meaningless: `^1.2-rc` does not
    // say which patch the candidate is a pre-release of.
    if pre.is_some() && (minor.is_none() || patch.is_none()) {
        return Err(Error::InvalidVersionRange(format!(
            "{whole}: '{text}' has a pre-release tag but not all three numbers"
        )));
    }
    let pre = pre.map_or_else(Vec::new, |pre| {
        pre.split('.').map(ToOwned::to_owned).collect()
    });

    Ok(Partial {
        major,
        minor,
        patch,
        pre,
    })
}

fn parse_token(token: &str, whole: &str) -> Result<Vec<Comparator>> {
    // Longest operator first, or `>=` is read as `>` followed by garbage.
    for (prefix, op) in [
        (">=", Op::GreaterEq),
        ("<=", Op::LessEq),
        (">", Op::Greater),
        ("<", Op::Less),
        ("=", Op::Exact),
    ] {
        if let Some(rest) = token.strip_prefix(prefix) {
            let partial = parse_partial(rest, whole)?;
            return Ok(match op {
                // `<1.2` means "below 1.2.0", and `>=1.2` means "1.2.0 or
                // above": the unspecified components round towards the bound
                // that makes the comparator mean what it reads as.
                Op::Exact => exact_comparators(&partial),
                _ => vec![Comparator {
                    op,
                    version: partial.lower(),
                }],
            });
        }
    }

    if let Some(rest) = token.strip_prefix('^') {
        let partial = parse_partial(rest, whole)?;
        return Ok(caret(&partial));
    }
    if let Some(rest) = token.strip_prefix('~') {
        let partial = parse_partial(rest, whole)?;
        return Ok(tilde(&partial));
    }

    let partial = parse_partial(token, whole)?;
    Ok(exact_comparators(&partial))
}

/// A bare or `=`-prefixed partial version pins the components that were
/// written and leaves the rest free: `1.2` is `>=1.2.0 <1.3.0`.
fn exact_comparators(p: &Partial) -> Vec<Comparator> {
    match (p.minor, p.patch) {
        (Some(_), Some(_)) => vec![Comparator {
            op: Op::Exact,
            version: p.lower(),
        }],
        (Some(minor), None) => bounded(p.lower(), Version::new(p.major, minor + 1, 0)),
        _ => bounded(p.lower(), Version::new(p.major + 1, 0, 0)),
    }
}

/// npm caret: compatible within the leftmost non-zero component, which is what
/// makes `^0.2.3` narrower than `^1.2.3`. A `0.x` version has no stability
/// promise, so the caret must not cross its minor.
fn caret(p: &Partial) -> Vec<Comparator> {
    let lower = p.lower();
    let upper = if p.major > 0 {
        Version::new(p.major + 1, 0, 0)
    } else {
        match (p.minor, p.patch) {
            (Some(0) | None, _) if p.minor.is_none() => Version::new(1, 0, 0),
            (Some(minor), Some(_)) if minor > 0 => Version::new(0, minor + 1, 0),
            (Some(minor), None) => Version::new(0, minor + 1, 0),
            (Some(_), Some(patch)) => Version::new(0, 0, patch + 1),
            (None, _) => Version::new(1, 0, 0),
        }
    };
    bounded(lower, upper)
}

/// npm tilde: allow patch moves when a patch was written, minor moves when it
/// was not.
fn tilde(p: &Partial) -> Vec<Comparator> {
    let lower = p.lower();
    let upper = match (p.minor, p.patch) {
        (Some(minor), _) => Version::new(p.major, minor + 1, 0),
        (None, _) => Version::new(p.major + 1, 0, 0),
    };
    bounded(lower, upper)
}

fn bounded(lower: Version, upper: Version) -> Vec<Comparator> {
    vec![
        Comparator {
            op: Op::GreaterEq,
            version: lower,
        },
        Comparator {
            op: Op::Less,
            version: upper,
        },
    ]
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn v(text: &str) -> Version {
        Version::parse(text).expect("test version parses")
    }

    fn r(text: &str) -> VersionRange {
        VersionRange::parse(text).expect("test range parses")
    }

    #[test]
    fn parses_and_renders() {
        assert_eq!(v("1.2.3").to_string(), "1.2.3");
        assert_eq!(v("0.11.0-alpha").to_string(), "0.11.0-alpha");
        // Build metadata is accepted and dropped: it is not part of precedence.
        assert_eq!(v("1.0.0+sha.abc").to_string(), "1.0.0");
    }

    #[test]
    fn rejects_malformed_versions() {
        for bad in [
            "", "1", "1.2", "1.2.3.4", "01.2.3", "1.2.x", "a.b.c", "1.0.0+",
        ] {
            assert!(Version::parse(bad).is_err(), "{bad} should not parse");
        }
    }

    #[test]
    fn orders_prereleases_before_their_release() {
        assert!(v("1.0.0-rc.1") < v("1.0.0"));
        assert!(v("1.0.0-alpha") < v("1.0.0-beta"));
        assert!(v("1.0.0-alpha.1") < v("1.0.0-alpha.2"));
        // Numeric identifiers rank below alphanumeric ones.
        assert!(v("1.0.0-1") < v("1.0.0-alpha"));
        // A shorter identifier set precedes a longer one with the same prefix.
        assert!(v("1.0.0-alpha") < v("1.0.0-alpha.1"));
        assert!(v("0.11.0") > v("0.2.0"));
    }

    #[test]
    fn caret_respects_the_leftmost_nonzero() {
        assert!(r("^1.2.3").matches(&v("1.9.0")));
        assert!(!r("^1.2.3").matches(&v("2.0.0")));
        assert!(!r("^1.2.3").matches(&v("1.2.2")));

        // The 0.x rule: a caret must not cross a minor that carries no promise.
        assert!(r("^0.2.3").matches(&v("0.2.9")));
        assert!(!r("^0.2.3").matches(&v("0.3.0")));
        assert!(r("^0.0.3").matches(&v("0.0.3")));
        assert!(!r("^0.0.3").matches(&v("0.0.4")));
    }

    #[test]
    fn tilde_allows_patch_moves() {
        assert!(r("~1.2.3").matches(&v("1.2.9")));
        assert!(!r("~1.2.3").matches(&v("1.3.0")));
        assert!(r("~1.2").matches(&v("1.2.9")));
        assert!(!r("~1.2").matches(&v("1.3.0")));
        assert!(r("~1").matches(&v("1.9.9")));
        assert!(!r("~1").matches(&v("2.0.0")));
    }

    #[test]
    fn conjunctions_and_partials() {
        let range = r(">=0.3 <1.0");
        assert!(range.matches(&v("0.3.0")));
        assert!(range.matches(&v("0.9.9")));
        assert!(!range.matches(&v("1.0.0")));
        assert!(!range.matches(&v("0.2.9")));

        // A bare partial pins what was written: npm reads `1.2` as `1.2.x`,
        // which is the behaviour the contract documents.
        let narrow = r("1.2");
        assert!(narrow.matches(&v("1.2.7")));
        assert!(!narrow.matches(&v("1.3.0")));
    }

    #[test]
    fn wildcard_accepts_anything_released() {
        assert!(r("*").matches(&v("0.0.1")));
        assert!(r("*").matches(&v("9.9.9")));
        assert!(VersionRange::any().matches(&v("1.0.0")));
    }

    #[test]
    fn a_caret_never_opts_into_a_prerelease() {
        // The rule that matters in practice: installing ^1.0.0 must not pull
        // 2.0.0-beta.1, and must not pull 1.1.0-rc.1 either.
        assert!(!r("^1.0.0").matches(&v("1.1.0-rc.1")));
        assert!(!r("^1.0.0").matches(&v("2.0.0-beta.1")));
        // Opting in explicitly works, within the same core version.
        assert!(r("^1.0.0-rc.0").matches(&v("1.0.0-rc.1")));
        assert!(!r("^1.0.0-rc.0").matches(&v("1.1.0-rc.1")));
    }

    #[test]
    fn unsupported_syntax_is_refused_not_guessed() {
        for bad in ["1.0.0 || 2.0.0", "1.2 - 1.5", "not-a-version", "^"] {
            assert!(
                VersionRange::parse(bad).is_err(),
                "{bad} should be refused rather than misparsed"
            );
        }
    }

    #[test]
    fn range_quotes_the_author() {
        assert_eq!(r(">=0.3 <1.0").as_str(), ">=0.3 <1.0");
    }

    #[test]
    fn revocation_matching_counts_prereleases_installation_does_not() {
        // The one place the two rules must disagree. A revocation window has
        // to catch the release candidate inside it; a dependency range must
        // not pull one in unasked.
        let window = r(">=1.0.0 <1.5.0");
        let rc = v("1.4.2-rc.1");
        assert!(window.matches_including_prereleases(&rc));
        assert!(!window.matches(&rc));
        // Releases behave identically under both.
        let released = v("1.4.2");
        assert!(window.matches(&released));
        assert!(window.matches_including_prereleases(&released));
        // The window edges keep plain semver ordering, which makes them
        // asymmetric. Both of these are literal readings, and a publisher
        // writing a revocation needs to know which they get:
        //   1.5.0-rc.1 < 1.5.0, so the upper bound covers it;
        //   1.0.0-alpha < 1.0.0, so the lower bound excludes it.
        assert!(window.matches_including_prereleases(&v("1.5.0-rc.1")));
        assert!(!window.matches_including_prereleases(&v("1.0.0-alpha")));
        // Which is why "everything before the fix" is written as the upper
        // bound alone.
        let before_the_fix = r("<1.5.0");
        assert!(before_the_fix.matches_including_prereleases(&v("1.0.0-alpha")));
        assert!(before_the_fix.matches_including_prereleases(&v("0.1.0")));
        assert!(!before_the_fix.matches_including_prereleases(&v("1.5.0")));
    }
}
