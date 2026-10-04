// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 EON contributors
//
// Additional permission under GNU GPL version 3 section 7:
// see LICENSE-EXCEPTION.md (EON Module ABI Exception 1.0).

//! Revocation.
//!
//! The spec lists revocation *before* signing, and this module exists for the
//! reason given there: signing without revocation only proves who shipped the
//! malicious version, it does not stop it.
//!
//! Four rules shape everything here, and each one is a decision that could
//! plausibly have gone the other way:
//!
//! * **Revocation is version-scoped.** The bad release is revoked, not the
//!   module. One bad version should not destroy a maintainer's project.
//! * **A fetch failure falls back to the last known list, never to "everything
//!   is fine".** An attacker who can block a network request must not be able
//!   to un-revoke, so an absent list is a reported condition rather than a
//!   clear one.
//! * **An older list never replaces a newer one.** Otherwise replaying
//!   yesterday's list is the same attack as blocking today's.
//! * **A revoked module is disabled and reported**, with reason and advisory
//!   link. Quiet removal teaches users to distrust the updater, which costs
//!   more than the one module ever could.
//!
//! The reasons are an enum, not free text, so a client can treat
//! `malicious-code` differently from `publisher-request` — and so the list
//! cannot become a channel for arbitrary prose shown to users.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{
    error::{Error, Result},
    module::{BuildProfile, SignatureEnvelope},
    semver::{Version, VersionRange},
    signature::{Artefact, Subject, TrustStore},
    time::{format_rfc3339, parse_rfc3339},
};

/// Why something was revoked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RevocationReason {
    /// The version does something hostile.
    MaliciousCode,
    /// The signing key is no longer trustworthy.
    KeyCompromise,
    /// A security flaw, without intent.
    SecurityVulnerability,
    /// The content violates a licence.
    LicenseViolation,
    /// A legal order required removal.
    LegalOrder,
    /// The publisher asked for it.
    PublisherRequest,
}

impl RevocationReason {
    /// The identifier as it appears in a list.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MaliciousCode => "malicious-code",
            Self::KeyCompromise => "key-compromise",
            Self::SecurityVulnerability => "security-vulnerability",
            Self::LicenseViolation => "license-violation",
            Self::LegalOrder => "legal-order",
            Self::PublisherRequest => "publisher-request",
        }
    }

    /// Whether a user should be told urgently rather than at leisure.
    ///
    /// A module pulled at the publisher's request is housekeeping; one pulled
    /// for malicious code is not, and flattening the two into "an update is
    /// available" is how the urgent case gets ignored.
    #[must_use]
    pub const fn is_urgent(self) -> bool {
        matches!(
            self,
            Self::MaliciousCode | Self::KeyCompromise | Self::SecurityVulnerability
        )
    }

    /// Message key for the user-visible text (see [`crate::i18n`]).
    #[must_use]
    pub const fn message_key(self) -> &'static str {
        match self {
            Self::MaliciousCode => "revoked.malicious-code",
            Self::KeyCompromise => "revoked.key-compromise",
            Self::SecurityVulnerability => "revoked.security-vulnerability",
            Self::LicenseViolation => "revoked.license-violation",
            Self::LegalOrder => "revoked.legal-order",
            Self::PublisherRequest => "revoked.publisher-request",
        }
    }
}

/// One revoked module, at one version or range of versions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevokedModule {
    /// Identifier of the module.
    pub id: String,
    /// Which versions. A bare version pins exactly that one; an npm range
    /// covers a window.
    pub versions: String,
    /// Why.
    pub reason: RevocationReason,
    /// When, RFC 3339.
    #[serde(rename = "revokedAt")]
    pub revoked_at: String,
    /// Where a person can read the detail.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub advisory: Option<String>,
}

/// One revoked signing key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevokedKey {
    /// Identifier of the key.
    #[serde(rename = "keyId")]
    pub key_id: String,
    /// Why.
    pub reason: RevocationReason,
    /// Where a person can read the detail.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub advisory: Option<String>,
}

/// A signed revocation list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationList {
    /// Schema version of this document.
    #[serde(rename = "schemaVersion")]
    pub schema_version: u32,
    /// When the list was issued, RFC 3339.
    #[serde(rename = "issuedAt")]
    pub issued_at: String,
    /// When a client should have a newer one, RFC 3339. Past this, the list is
    /// stale and the client says so.
    #[serde(rename = "nextUpdate")]
    pub next_update: String,
    /// Revoked module versions.
    #[serde(default)]
    pub revoked: Vec<RevokedModule>,
    /// Revoked signing keys.
    #[serde(default, rename = "revokedKeys")]
    pub revoked_keys: Vec<RevokedKey>,
    /// Detached signature over the list. Required before the list is trusted;
    /// optional in the type so an unsigned draft can be parsed and inspected
    /// by tooling, never installed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<SignatureEnvelope>,
}

/// The identifier a revocation list signature binds to.
///
/// The list has no version of its own, so `issuedAt` plays that role: it is
/// what makes one list's signature non-transferable to another list.
pub const REVOCATION_SUBJECT_ID: &str = "org.eon.stream.revocation";

impl RevocationList {
    /// Parse a list document.
    ///
    /// # Errors
    ///
    /// [`Error::MalformedJson`] if the bytes are not the expected JSON, or
    /// [`Error::InvalidRevocationList`] if the document parses but is not
    /// usable — an unknown schema version, a malformed timestamp, a `versions`
    /// field that is not a range, or a `nextUpdate` that precedes `issuedAt`.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let list: Self = serde_json::from_slice(bytes).map_err(|e| Error::MalformedJson {
            message: e.to_string(),
        })?;
        list.validate()?;
        Ok(list)
    }

    /// Check the document's internal consistency.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidRevocationList`] with what is wrong.
    pub fn validate(&self) -> Result<()> {
        let bad = |detail: String| Error::InvalidRevocationList(detail);
        if self.schema_version != 0 {
            return Err(bad(format!(
                "schemaVersion is {}, this build reads 0",
                self.schema_version
            )));
        }
        let issued = self.issued_at_unix()?;
        let next = parse_rfc3339(&self.next_update).map_err(|e| bad(format!("nextUpdate: {e}")))?;
        if next <= issued {
            return Err(bad(
                "nextUpdate is not after issuedAt, so the list is stale the moment it is issued"
                    .to_owned(),
            ));
        }
        for entry in &self.revoked {
            VersionRange::parse(&entry.versions).map_err(|e| {
                bad(format!(
                    "'{}' has an unusable versions field: {e}",
                    entry.id
                ))
            })?;
            parse_rfc3339(&entry.revoked_at)
                .map_err(|e| bad(format!("'{}' revokedAt: {e}", entry.id)))?;
        }
        let mut keys: Vec<&str> = self
            .revoked_keys
            .iter()
            .map(|k| k.key_id.as_str())
            .collect();
        keys.sort_unstable();
        let count = keys.len();
        keys.dedup();
        if keys.len() != count {
            return Err(bad("a key is revoked twice".to_owned()));
        }
        Ok(())
    }

    /// `issuedAt` as Unix seconds.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidRevocationList`] if it is malformed.
    pub fn issued_at_unix(&self) -> Result<i64> {
        parse_rfc3339(&self.issued_at)
            .map_err(|e| Error::InvalidRevocationList(format!("issuedAt: {e}")))
    }

    /// `nextUpdate` as Unix seconds.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidRevocationList`] if it is malformed.
    pub fn next_update_unix(&self) -> Result<i64> {
        parse_rfc3339(&self.next_update)
            .map_err(|e| Error::InvalidRevocationList(format!("nextUpdate: {e}")))
    }

    /// The subject a signature over this list binds to.
    ///
    /// The hash covers the list **with the signature member removed**, which
    /// is what "detached" has to mean for a document that carries its own
    /// signature: hashing the document including the signature is not
    /// something a signer can do.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidRevocationList`] if the list cannot be re-serialised.
    pub fn signing_subject(&self) -> Result<Subject> {
        let mut unsigned = self.clone();
        unsigned.signature = None;
        let bytes = serde_json::to_vec(&unsigned).map_err(|e| {
            Error::InvalidRevocationList(format!("could not re-serialise the list: {e}"))
        })?;
        Ok(Subject::of(REVOCATION_SUBJECT_ID, &self.issued_at, &bytes))
    }

    /// Verify the list's signature against `trust`.
    ///
    /// # Errors
    ///
    /// [`Error::SignatureMissing`] when the list is unsigned, or whatever
    /// [`TrustStore::verify`] reports.
    pub fn verify(&self, trust: &TrustStore, build: BuildProfile, now: i64) -> Result<()> {
        let envelope = self
            .signature
            .as_ref()
            .ok_or_else(|| Error::SignatureMissing(REVOCATION_SUBJECT_ID.to_owned()))?;
        let subject = self.signing_subject()?;
        trust.verify(envelope, &subject, Artefact::Revocation, build, now)?;
        Ok(())
    }

    /// Whether this list revokes `version` of `id`.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidVersionRange`] if an entry's `versions` field is
    /// unusable. Validated at parse time, so reaching this means the list was
    /// built in memory and not checked.
    pub fn status(&self, id: &str, version: &Version) -> Result<RevocationStatus> {
        for entry in self.revoked.iter().filter(|e| e.id == id) {
            let range = VersionRange::parse(&entry.versions)?;
            // Pre-releases count here; see
            // `VersionRange::matches_including_prereleases` for why this is
            // the opposite of the installation rule.
            if range.matches_including_prereleases(version) {
                return Ok(RevocationStatus::Revoked {
                    reason: entry.reason,
                    revoked_at: entry.revoked_at.clone(),
                    advisory: entry.advisory.clone(),
                });
            }
        }
        Ok(RevocationStatus::Clear)
    }

    /// Revoked key ids mapped to their reason, in the shape
    /// [`TrustStore::revoke_keys`] takes.
    #[must_use]
    pub fn revoked_key_map(&self) -> BTreeMap<String, String> {
        self.revoked_keys
            .iter()
            .map(|k| (k.key_id.clone(), k.reason.as_str().to_owned()))
            .collect()
    }
}

/// Whether a specific module version is revoked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevocationStatus {
    /// Not named by the list.
    Clear,
    /// Named by the list.
    Revoked {
        /// Why.
        reason: RevocationReason,
        /// When, RFC 3339.
        revoked_at: String,
        /// Where to read more.
        advisory: Option<String>,
    },
}

/// How current the held list is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevocationFreshness {
    /// Held and inside its `nextUpdate`.
    Fresh {
        /// When a newer list is due, RFC 3339.
        next_update: String,
    },
    /// Held, but past `nextUpdate`. Still applied — a stale list is far
    /// better than none — and the staleness is surfaced.
    Stale {
        /// When a newer list was due, RFC 3339.
        next_update: String,
        /// How long ago that was, in seconds.
        overdue_seconds: i64,
    },
    /// No list has ever been obtained. **Not** the same as "nothing is
    /// revoked", and the API makes that hard to confuse by having no
    /// `is_clear`-style shortcut.
    Absent,
}

impl RevocationFreshness {
    /// Whether the client should warn the user about its revocation data.
    #[must_use]
    pub const fn needs_attention(&self) -> bool {
        !matches!(self, Self::Fresh { .. })
    }
}

/// The last known good revocation list.
///
/// Holds at most one list and only ever moves forward. Persisting this across
/// restarts is the whole point: a client that forgets what was revoked when it
/// is offline has no revocation at all.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationStore {
    /// The list currently held, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    held: Option<RevocationList>,
}

impl RevocationStore {
    /// A store that holds nothing.
    #[must_use]
    pub fn new() -> Self {
        Self { held: None }
    }

    /// The list currently held.
    #[must_use]
    pub fn held(&self) -> Option<&RevocationList> {
        self.held.as_ref()
    }

    /// Accept a newer list, verifying it first.
    ///
    /// Returns the keys the new list revokes, so the caller can apply them to
    /// its trust set in the same step — forgetting that is how a compromised
    /// key keeps working.
    ///
    /// # Errors
    ///
    /// [`Error::RevocationRollback`] when the offered list is not newer than
    /// the one held, [`Error::SignatureMissing`] when it is unsigned, or
    /// whatever verification reports. On any error the held list is left
    /// exactly as it was.
    pub fn accept(
        &mut self,
        offered: RevocationList,
        trust: &TrustStore,
        build: BuildProfile,
        now: i64,
    ) -> Result<BTreeMap<String, String>> {
        offered.validate()?;
        offered.verify(trust, build, now)?;

        let offered_at = offered.issued_at_unix()?;
        if let Some(held) = &self.held {
            let held_at = held.issued_at_unix()?;
            // Strictly newer. Equal is refused too: two different lists with
            // one `issuedAt` is either a mistake or a replay, and neither is
            // worth guessing about.
            if offered_at <= held_at {
                return Err(Error::RevocationRollback {
                    offered: offered.issued_at.clone(),
                    held: held.issued_at.clone(),
                });
            }
        }
        let keys = offered.revoked_key_map();
        self.held = Some(offered);
        Ok(keys)
    }

    /// Whether `version` of `id` is revoked by the held list.
    ///
    /// With no list held the answer is [`RevocationStatus::Clear`] — there is
    /// nothing else it could be — which is exactly why
    /// [`freshness`](Self::freshness) must be consulted alongside it rather
    /// than this being read as "safe".
    ///
    /// # Errors
    ///
    /// [`Error::InvalidVersionRange`] if the held list has an unusable entry.
    pub fn status(&self, id: &str, version: &Version) -> Result<RevocationStatus> {
        match &self.held {
            None => Ok(RevocationStatus::Clear),
            Some(list) => list.status(id, version),
        }
    }

    /// How current the held list is at `now`.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidRevocationList`] if the held list has a malformed
    /// `nextUpdate`.
    pub fn freshness(&self, now: i64) -> Result<RevocationFreshness> {
        let Some(list) = &self.held else {
            return Ok(RevocationFreshness::Absent);
        };
        let next = list.next_update_unix()?;
        Ok(if now < next {
            RevocationFreshness::Fresh {
                next_update: list.next_update.clone(),
            }
        } else {
            RevocationFreshness::Stale {
                next_update: list.next_update.clone(),
                overdue_seconds: now - next,
            }
        })
    }

    /// A one-line summary for a status display.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidRevocationList`] if the held list is malformed.
    pub fn summary(&self, now: i64) -> Result<String> {
        Ok(match self.freshness(now)? {
            RevocationFreshness::Absent => "no revocation list has been fetched".to_owned(),
            RevocationFreshness::Fresh { next_update } => {
                let count = self.held.as_ref().map_or(0, |l| l.revoked.len());
                format!("{count} revoked version(s), next update due {next_update}")
            }
            RevocationFreshness::Stale {
                next_update,
                overdue_seconds,
            } => {
                let days = overdue_seconds / 86_400;
                format!(
                    "revocation list is {days} day(s) overdue (was due {next_update}); \
                     still applying the last known one"
                )
            }
        })
    }

    /// Serialise for persistence.
    ///
    /// # Errors
    ///
    /// [`Error::Storage`] if serialisation fails.
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self).map_err(|e| Error::Storage {
            message: e.to_string(),
        })
    }

    /// Read back a persisted store.
    ///
    /// # Errors
    ///
    /// [`Error::Storage`] if the stored bytes are not a store this build
    /// reads.
    pub fn from_json(text: &str) -> Result<Self> {
        let store: Self = serde_json::from_str(text).map_err(|e| Error::Storage {
            message: e.to_string(),
        })?;
        if let Some(list) = &store.held {
            list.validate()?;
        }
        Ok(store)
    }
}

/// What applying a revocation list did to one installed module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevocationAction {
    /// Identifier of the module.
    pub module_id: String,
    /// Its installed version.
    pub version: String,
    /// Why it was revoked.
    pub reason: RevocationReason,
    /// Where to read more.
    pub advisory: Option<String>,
    /// Whether this module was still enabled before this ran. A module already
    /// disabled is reported once, not every time the list is applied.
    pub was_enabled: bool,
}

impl RevocationAction {
    /// A line fit to show a person, naming the reason and the advisory.
    ///
    /// Reporting is not optional: a module that vanishes without explanation
    /// teaches users that the updater removes things at random.
    #[must_use]
    pub fn describe(&self) -> String {
        let urgency = if self.reason.is_urgent() {
            "disabled"
        } else {
            "disabled (no longer distributed)"
        };
        match &self.advisory {
            Some(advisory) => format!(
                "{} {} {urgency}: {} — {advisory}",
                self.module_id,
                self.version,
                self.reason.as_str()
            ),
            None => format!(
                "{} {} {urgency}: {}",
                self.module_id,
                self.version,
                self.reason.as_str()
            ),
        }
    }
}

/// Render a Unix timestamp the way a list carries one, for building lists in
/// tests and tooling.
#[must_use]
pub fn timestamp(unix_seconds: i64) -> String {
    format_rfc3339(unix_seconds)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::{
        module::SignatureAlgorithm,
        signature::{KeyPurpose, TrustedKey},
    };
    use base64::Engine as _;

    const TEST_SECRET: [u8; 32] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ];

    const NOW: i64 = 1_780_000_000;

    fn signing_key() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&TEST_SECRET)
    }

    fn trust() -> TrustStore {
        TrustStore::from_keys(vec![TrustedKey {
            key_id: "release-2026-a".to_owned(),
            purpose: KeyPurpose::Release,
            public_key: base64::engine::general_purpose::STANDARD
                .encode(signing_key().verifying_key().to_bytes()),
            not_before: "2026-01-01T00:00:00Z".to_owned(),
            not_after: "2027-01-01T00:00:00Z".to_owned(),
            comment: None,
        }])
    }

    fn list(issued: i64, revoked: Vec<RevokedModule>) -> RevocationList {
        RevocationList {
            schema_version: 0,
            issued_at: timestamp(issued),
            next_update: timestamp(issued + 7 * 86_400),
            revoked,
            revoked_keys: Vec::new(),
            signature: None,
        }
    }

    fn sign(mut list: RevocationList) -> RevocationList {
        use ed25519_dalek::Signer as _;
        let subject = list.signing_subject().unwrap();
        let signature = signing_key().sign(&subject.canonical_bytes());
        list.signature = Some(SignatureEnvelope {
            algorithm: SignatureAlgorithm::Ed25519,
            key_id: "release-2026-a".to_owned(),
            value: base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()),
            signed_at: Some(list.issued_at.clone()),
        });
        list
    }

    fn entry(id: &str, versions: &str, reason: RevocationReason) -> RevokedModule {
        RevokedModule {
            id: id.to_owned(),
            versions: versions.to_owned(),
            reason,
            revoked_at: timestamp(NOW - 86_400),
            advisory: Some("https://example.org/advisory/1".to_owned()),
        }
    }

    fn v(text: &str) -> Version {
        Version::parse(text).unwrap()
    }

    #[test]
    fn revocation_is_version_scoped() {
        // One bad release must not destroy the maintainer's project.
        let list = list(
            NOW,
            vec![entry(
                "community.example.bad",
                "1.4.2",
                RevocationReason::MaliciousCode,
            )],
        );
        assert!(matches!(
            list.status("community.example.bad", &v("1.4.2")).unwrap(),
            RevocationStatus::Revoked { .. }
        ));
        assert_eq!(
            list.status("community.example.bad", &v("1.4.3")).unwrap(),
            RevocationStatus::Clear
        );
        assert_eq!(
            list.status("community.example.bad", &v("1.4.1")).unwrap(),
            RevocationStatus::Clear
        );
        assert_eq!(
            list.status("community.example.good", &v("1.4.2")).unwrap(),
            RevocationStatus::Clear
        );
    }

    #[test]
    fn a_window_catches_the_prereleases_inside_it() {
        let window = list(
            NOW,
            vec![entry(
                "community.example.bad",
                ">=1.0.0 <1.5.0",
                RevocationReason::SecurityVulnerability,
            )],
        );
        for version in ["1.0.0", "1.4.2", "1.4.2-rc.1", "1.5.0-rc.1"] {
            assert!(
                matches!(
                    window.status("community.example.bad", &v(version)).unwrap(),
                    RevocationStatus::Revoked { .. }
                ),
                "{version} is inside the revoked window"
            );
        }
        assert_eq!(
            window.status("community.example.bad", &v("1.5.0")).unwrap(),
            RevocationStatus::Clear
        );
        // The lower edge keeps semver ordering, so a pre-release of the lower
        // bound itself falls outside. A publisher meaning "everything before
        // the fix" writes the upper bound alone -- see
        // `VersionRange::matches_including_prereleases`.
        assert_eq!(
            window
                .status("community.example.bad", &v("1.0.0-alpha"))
                .unwrap(),
            RevocationStatus::Clear
        );
        let open_below = list(
            NOW,
            vec![entry(
                "community.example.bad",
                "<1.5.0",
                RevocationReason::SecurityVulnerability,
            )],
        );
        assert!(matches!(
            open_below
                .status("community.example.bad", &v("1.0.0-alpha"))
                .unwrap(),
            RevocationStatus::Revoked { .. }
        ));
    }

    #[test]
    fn a_signed_list_is_accepted_and_an_unsigned_one_is_not() {
        let mut store = RevocationStore::new();
        let unsigned = list(NOW, vec![]);
        assert!(matches!(
            store.accept(unsigned, &trust(), BuildProfile::Stream, NOW),
            Err(Error::SignatureMissing(_))
        ));
        assert!(store.held().is_none());

        store
            .accept(sign(list(NOW, vec![])), &trust(), BuildProfile::Stream, NOW)
            .unwrap();
        assert!(store.held().is_some());
    }

    #[test]
    fn an_older_list_never_replaces_a_newer_one() {
        // Replaying yesterday's list is the same attack as blocking today's.
        let mut store = RevocationStore::new();
        let newer = sign(list(
            NOW,
            vec![entry(
                "community.example.bad",
                "1.4.2",
                RevocationReason::MaliciousCode,
            )],
        ));
        store
            .accept(newer, &trust(), BuildProfile::Stream, NOW)
            .unwrap();

        let older = sign(list(NOW - 86_400, vec![]));
        assert!(matches!(
            store.accept(older, &trust(), BuildProfile::Stream, NOW),
            Err(Error::RevocationRollback { .. })
        ));
        // And the revocation it would have dropped is still in force.
        assert!(matches!(
            store.status("community.example.bad", &v("1.4.2")).unwrap(),
            RevocationStatus::Revoked { .. }
        ));
    }

    #[test]
    fn a_list_with_the_same_issued_at_is_refused_too() {
        let mut store = RevocationStore::new();
        store
            .accept(sign(list(NOW, vec![])), &trust(), BuildProfile::Stream, NOW)
            .unwrap();
        let same_time = sign(list(
            NOW,
            vec![entry("x.y", "1.0.0", RevocationReason::LegalOrder)],
        ));
        assert!(store
            .accept(same_time, &trust(), BuildProfile::Stream, NOW)
            .is_err());
    }

    #[test]
    fn a_tampered_list_does_not_verify() {
        let mut signed = sign(list(NOW, vec![]));
        // Add a revocation after signing: the hash covers the list without its
        // signature, so this must be caught.
        signed
            .revoked
            .push(entry("x.y", "1.0.0", RevocationReason::LegalOrder));
        let mut store = RevocationStore::new();
        assert!(store
            .accept(signed, &trust(), BuildProfile::Stream, NOW)
            .is_err());
    }

    #[test]
    fn removing_a_revocation_after_signing_is_caught_as_well() {
        // The direction that actually benefits an attacker.
        let mut signed = sign(list(
            NOW,
            vec![entry("x.y", "1.0.0", RevocationReason::MaliciousCode)],
        ));
        signed.revoked.clear();
        let mut store = RevocationStore::new();
        assert!(store
            .accept(signed, &trust(), BuildProfile::Stream, NOW)
            .is_err());
    }

    #[test]
    fn an_absent_list_is_a_reported_condition_not_a_clear_one() {
        let store = RevocationStore::new();
        assert_eq!(store.freshness(NOW).unwrap(), RevocationFreshness::Absent);
        assert!(store.freshness(NOW).unwrap().needs_attention());
        assert!(store.summary(NOW).unwrap().contains("no revocation list"));
    }

    #[test]
    fn a_stale_list_is_still_applied() {
        // An attacker who can block the network must not be able to un-revoke.
        let mut store = RevocationStore::new();
        store
            .accept(
                sign(list(
                    NOW,
                    vec![entry(
                        "community.example.bad",
                        "1.4.2",
                        RevocationReason::MaliciousCode,
                    )],
                )),
                &trust(),
                BuildProfile::Stream,
                NOW,
            )
            .unwrap();

        let much_later = NOW + 30 * 86_400;
        match store.freshness(much_later).unwrap() {
            RevocationFreshness::Stale {
                overdue_seconds, ..
            } => assert!(overdue_seconds > 0),
            other => panic!("expected staleness, got {other:?}"),
        }
        // Still revoked.
        assert!(matches!(
            store.status("community.example.bad", &v("1.4.2")).unwrap(),
            RevocationStatus::Revoked { .. }
        ));
        assert!(store.summary(much_later).unwrap().contains("overdue"));
    }

    #[test]
    fn accepting_a_list_hands_back_the_keys_it_revokes() {
        let mut inner = list(NOW, vec![]);
        inner.revoked_keys.push(RevokedKey {
            key_id: "module-2026-a".to_owned(),
            reason: RevocationReason::KeyCompromise,
            advisory: None,
        });
        let mut store = RevocationStore::new();
        let keys = store
            .accept(sign(inner), &trust(), BuildProfile::Stream, NOW)
            .unwrap();
        assert_eq!(
            keys.get("module-2026-a").map(String::as_str),
            Some("key-compromise")
        );
    }

    #[test]
    fn next_update_must_follow_issued_at() {
        let mut inner = list(NOW, vec![]);
        inner.next_update = inner.issued_at.clone();
        assert!(inner.validate().is_err());
    }

    #[test]
    fn an_unknown_reason_does_not_parse() {
        // Reasons are enumerated so a client can treat malicious-code
        // differently from publisher-request, and so the list cannot become a
        // channel for arbitrary prose.
        let json = br#"{
            "schemaVersion": 0,
            "issuedAt": "2026-09-25T10:00:00Z",
            "nextUpdate": "2026-10-02T10:00:00Z",
            "revoked": [{"id":"x.y","versions":"1.0.0","reason":"we felt like it",
                         "revokedAt":"2026-09-24T18:30:00Z"}]
        }"#;
        assert!(RevocationList::parse(json).is_err());
    }

    #[test]
    fn an_unusable_versions_field_is_caught_at_parse_time() {
        let json = br#"{
            "schemaVersion": 0,
            "issuedAt": "2026-09-25T10:00:00Z",
            "nextUpdate": "2026-10-02T10:00:00Z",
            "revoked": [{"id":"x.y","versions":"1.0.0 || 2.0.0","reason":"legal-order",
                         "revokedAt":"2026-09-24T18:30:00Z"}]
        }"#;
        assert!(RevocationList::parse(json).is_err());
    }

    #[test]
    fn the_spec_example_parses() {
        // The document shape from docs/signing-and-revocation.md, so the two
        // cannot drift apart unnoticed.
        let json = br#"{
            "schemaVersion": 0,
            "issuedAt": "2026-09-25T10:00:00Z",
            "nextUpdate": "2026-10-02T10:00:00Z",
            "revoked": [
                {
                  "id": "community.example.badmodule",
                  "versions": "1.4.2",
                  "reason": "malicious-code",
                  "revokedAt": "2026-09-24T18:30:00Z",
                  "advisory": "https://github.com/EON-Extensible-Open-Network/eon-stream-core/security/advisories/GHSA-xxxx"
                }
            ],
            "revokedKeys": [{ "keyId": "module-2026-a", "reason": "key-compromise" }]
        }"#;
        let list = RevocationList::parse(json).unwrap();
        assert_eq!(list.revoked.len(), 1);
        assert_eq!(list.revoked_keys.len(), 1);
        assert!(matches!(
            list.status("community.example.badmodule", &v("1.4.2"))
                .unwrap(),
            RevocationStatus::Revoked {
                reason: RevocationReason::MaliciousCode,
                ..
            }
        ));
    }

    #[test]
    fn the_store_round_trips_through_json() {
        let mut store = RevocationStore::new();
        store
            .accept(
                sign(list(
                    NOW,
                    vec![entry("x.y", "1.0.0", RevocationReason::LegalOrder)],
                )),
                &trust(),
                BuildProfile::Stream,
                NOW,
            )
            .unwrap();
        let text = store.to_json().unwrap();
        let back = RevocationStore::from_json(&text).unwrap();
        assert!(matches!(
            back.status("x.y", &v("1.0.0")).unwrap(),
            RevocationStatus::Revoked { .. }
        ));
    }

    #[test]
    fn urgency_separates_the_two_kinds_of_revocation() {
        assert!(RevocationReason::MaliciousCode.is_urgent());
        assert!(RevocationReason::KeyCompromise.is_urgent());
        assert!(!RevocationReason::PublisherRequest.is_urgent());
        assert!(!RevocationReason::LicenseViolation.is_urgent());
    }

    #[test]
    fn an_action_names_the_reason_and_the_advisory() {
        let action = RevocationAction {
            module_id: "community.example.bad".to_owned(),
            version: "1.4.2".to_owned(),
            reason: RevocationReason::MaliciousCode,
            advisory: Some("https://example.org/a".to_owned()),
            was_enabled: true,
        };
        let line = action.describe();
        assert!(line.contains("malicious-code"), "{line}");
        assert!(line.contains("https://example.org/a"), "{line}");
    }
}
