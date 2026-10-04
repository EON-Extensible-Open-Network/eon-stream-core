// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 EON contributors
//
// Additional permission under GNU GPL version 3 section 7:
// see LICENSE-EXCEPTION.md (EON Module ABI Exception 1.0).

//! The updater.
//!
//! Decides whether there is a newer release and whether the bytes offered are
//! the ones that were signed. It **downloads nothing and installs nothing**:
//! that is the host's job, because this crate performs no I/O and because an
//! updater that can also write to disk is the most attractive thing in the
//! application to compromise.
//!
//! ## Three rules, and the one that is easy to get wrong
//!
//! * **The manifest must be signed by a release key.** An unsigned manifest is
//!   not "an update of unknown provenance", it is a stranger choosing which
//!   binary you run.
//! * **A version never goes backwards** (madde 39). This is the one that is
//!   easy to get wrong, because the naive check is "offered != current" and
//!   that accepts a *downgrade* — which is how a patched vulnerability gets
//!   reintroduced by an attacker who can only replay an old, validly signed
//!   manifest. So the comparison is ordered, and a lower version is a reported
//!   refusal rather than silence.
//! * **The artefact hash is checked against the signed manifest**, not against
//!   a hash that came with the download. A checksum served next to the file it
//!   describes proves only that nobody corrupted it in transit.
//!
//! ## The alpha version scheme
//!
//! Tags count the digits after the dot as an alpha counter, trailing zero
//! dropped: `v0.19` is the twentieth alpha and is followed by `v0.2`, the
//! twenty-first. Cargo requires three-component semver, so the crate version
//! is `0.19.0-alpha`. The consequence is that **semver ordering is not build
//! order** during the alpha: `0.19.0` compares as ahead of `0.2.0`.
//!
//! That is a real hazard for an updater, so this module does not try to be
//! clever about it. Within a channel it compares versions as semver and says
//! so; [`ReleaseManifest::released_at`] is what orders the alpha line, and
//! [`UpdateCheck::evaluate`] uses the release date as the tie-breaker when
//! semver would disagree with it. A client that trusted semver alone would
//! refuse `v0.2` as a downgrade from `v0.19` and then never update again.

use serde::{Deserialize, Serialize};

use crate::{
    error::{Error, Result},
    module::{BuildProfile, SignatureEnvelope},
    semver::Version,
    settings::UpdateChannel,
    signature::{content_hash, Artefact, Subject, TrustStore},
    time::parse_rfc3339,
};

/// Release manifest schema version this build reads.
pub const RELEASE_SCHEMA_VERSION: u32 = 0;

/// A CPU architecture a release is built for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Arch {
    /// 64-bit x86.
    #[serde(rename = "x86_64")]
    X86_64,
    /// 64-bit ARM.
    #[serde(rename = "aarch64")]
    Aarch64,
}

impl Arch {
    /// The architecture this build runs on, or `None` on a target the manifest
    /// vocabulary has no word for.
    #[must_use]
    pub const fn host() -> Option<Self> {
        if cfg!(target_arch = "x86_64") {
            Some(Self::X86_64)
        } else if cfg!(target_arch = "aarch64") {
            Some(Self::Aarch64)
        } else {
            None
        }
    }

    /// The identifier as it appears in a manifest.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::X86_64 => "x86_64",
            Self::Aarch64 => "aarch64",
        }
    }
}

/// One downloadable file in a release.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Artifact {
    /// Operating system it is built for.
    pub platform: crate::module::Platform,
    /// Architecture it is built for.
    pub arch: Arch,
    /// File name as published.
    pub filename: String,
    /// Size in bytes. Checked alongside the hash so a truncated download is
    /// reported as truncated rather than as a hash mismatch.
    pub size: u64,
    /// Lowercase hex SHA-256 of the file.
    pub sha256: String,
    /// Where to fetch it.
    pub url: String,
}

impl Artifact {
    /// Whether `bytes` are the file this artefact describes.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidReleaseManifest`] on a size mismatch, or
    /// [`Error::ContentHashMismatch`] when the hash differs — two errors
    /// rather than one because a size mismatch is almost always a truncated
    /// download and a hash mismatch almost never is.
    pub fn verify(&self, bytes: &[u8]) -> Result<()> {
        if bytes.len() as u64 != self.size {
            return Err(Error::InvalidReleaseManifest(format!(
                "{} is {} bytes, the manifest says {}",
                self.filename,
                bytes.len(),
                self.size
            )));
        }
        let actual = content_hash(bytes);
        if actual != self.sha256.to_ascii_lowercase() {
            return Err(Error::ContentHashMismatch {
                expected: self.sha256.to_ascii_lowercase(),
                actual,
            });
        }
        Ok(())
    }
}

/// A signed description of one release.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ReleaseManifest {
    /// Schema version of this document.
    pub schema_version: u32,
    /// Which product. `eon-stream` or `eon-edu`; a build never updates itself
    /// from the other one's manifest.
    pub product: String,
    /// Which line this release belongs to.
    pub channel: UpdateChannel,
    /// The release version, three-component semver.
    pub version: String,
    /// The tag as published, which during the alpha is not the crate version:
    /// `v0.12` for `0.12.0-alpha`. Carried so a client can show the user the
    /// name they will see on the releases page.
    pub tag: String,
    /// When it was published, RFC 3339. This is what orders the alpha line,
    /// where semver ordering and build order disagree.
    pub released_at: String,
    /// Where to read what changed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes_url: Option<String>,
    /// The files.
    pub artifacts: Vec<Artifact>,
    /// Detached signature over the manifest without this member.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<SignatureEnvelope>,
}

impl ReleaseManifest {
    /// Parse a release manifest.
    ///
    /// # Errors
    ///
    /// [`Error::MalformedJson`] if the bytes are not the expected JSON, or
    /// [`Error::InvalidReleaseManifest`] if it parses but is not usable.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let manifest: Self = serde_json::from_slice(bytes).map_err(|e| Error::MalformedJson {
            message: e.to_string(),
        })?;
        manifest.validate()?;
        Ok(manifest)
    }

    /// Check the document's internal consistency.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidReleaseManifest`] with what is wrong, or
    /// [`Error::InvalidVersion`] if the version is malformed.
    pub fn validate(&self) -> Result<()> {
        let bad = |detail: String| Error::InvalidReleaseManifest(detail);
        if self.schema_version != RELEASE_SCHEMA_VERSION {
            return Err(bad(format!(
                "schemaVersion is {}, this build reads {RELEASE_SCHEMA_VERSION}",
                self.schema_version
            )));
        }
        if self.product.is_empty() {
            return Err(bad("product is empty".to_owned()));
        }
        let _version = Version::parse(&self.version)?;
        parse_rfc3339(&self.released_at).map_err(|e| bad(format!("releasedAt: {e}")))?;
        if self.artifacts.is_empty() {
            return Err(bad("the release carries no artefacts".to_owned()));
        }
        for artifact in &self.artifacts {
            if artifact.sha256.len() != 64
                || !artifact.sha256.chars().all(|c| c.is_ascii_hexdigit())
            {
                return Err(bad(format!(
                    "{}: sha256 is not 64 hex characters",
                    artifact.filename
                )));
            }
            if artifact.size == 0 {
                return Err(bad(format!("{}: size is 0", artifact.filename)));
            }
            // Only HTTPS. An update fetched over plain HTTP is a download an
            // attacker on the path chooses, and while the signature would
            // still catch a swap, there is no reason to hand them the attempt.
            if !artifact.url.starts_with("https://") {
                return Err(bad(format!("{}: url must be https", artifact.filename)));
            }
            validate_filename(&artifact.filename)?;
        }
        Ok(())
    }

    /// The release version.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidVersion`] if it is malformed.
    pub fn parsed_version(&self) -> Result<Version> {
        Version::parse(&self.version)
    }

    /// When it was published, as Unix seconds.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidReleaseManifest`] if the timestamp is malformed.
    pub fn released_at_unix(&self) -> Result<i64> {
        parse_rfc3339(&self.released_at)
            .map_err(|e| Error::InvalidReleaseManifest(format!("releasedAt: {e}")))
    }

    /// The subject a signature over this manifest binds to.
    ///
    /// The hash covers the manifest with the signature member removed, which
    /// is the only thing "detached" can mean for a document carrying its own
    /// signature.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidReleaseManifest`] if the manifest cannot be
    /// re-serialised.
    pub fn signing_subject(&self) -> Result<Subject> {
        let mut unsigned = self.clone();
        unsigned.signature = None;
        let bytes = serde_json::to_vec(&unsigned).map_err(|e| {
            Error::InvalidReleaseManifest(format!("could not re-serialise the manifest: {e}"))
        })?;
        Ok(Subject::of(&self.product, &self.version, &bytes))
    }

    /// The artefact for a platform and architecture.
    ///
    /// # Errors
    ///
    /// [`Error::NoArtifactForPlatform`] when the release has nothing for it.
    pub fn artifact_for(&self, platform: crate::module::Platform, arch: Arch) -> Result<&Artifact> {
        self.artifacts
            .iter()
            .find(|a| a.platform == platform && a.arch == arch)
            .ok_or_else(|| Error::NoArtifactForPlatform {
                version: self.version.clone(),
                platform: platform.as_str().to_owned(),
                arch: arch.as_str().to_owned(),
            })
    }
}

/// A published file name, with path separators refused.
///
/// The host will join this onto a directory. `../` in it would write outside
/// that directory, which is the oldest path bug there is.
fn validate_filename(filename: &str) -> Result<()> {
    let bad = |why: &str| {
        Err(Error::InvalidReleaseManifest(format!(
            "filename '{filename}' {why}"
        )))
    };
    if filename.is_empty() || filename.len() > 255 {
        return bad("must be between 1 and 255 characters");
    }
    if filename.contains('/') || filename.contains('\\') || filename.contains(':') {
        return bad("must be a bare file name with no path");
    }
    if filename == "." || filename == ".." || filename.starts_with('.') {
        return bad("must be an ordinary file name");
    }
    if filename.chars().any(char::is_control) {
        return bad("contains a control character");
    }
    Ok(())
}

/// What the updater concluded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateDecision {
    /// Nothing newer is offered.
    UpToDate {
        /// The version currently running.
        current: String,
    },
    /// A newer release exists, with the file for this machine.
    Available {
        /// The offered version.
        version: String,
        /// The tag as published, which is what the user will see.
        tag: String,
        /// The file for this platform and architecture.
        artifact: Artifact,
        /// Where to read what changed.
        notes_url: Option<String>,
    },
    /// The manifest offers an older version. Reported rather than ignored: a
    /// replayed old manifest is an attack, not a non-event (madde 39).
    Downgrade {
        /// The version currently running.
        current: String,
        /// The older version that was offered.
        offered: String,
    },
    /// The manifest is for another release line than the one configured.
    WrongChannel {
        /// The channel the manifest declares.
        offered: UpdateChannel,
        /// The channel this client watches.
        configured: UpdateChannel,
    },
    /// The manifest is for a different product.
    WrongProduct {
        /// The product the manifest declares.
        offered: String,
        /// The product this build is.
        expected: String,
    },
}

impl UpdateDecision {
    /// Whether there is something for the user to act on.
    #[must_use]
    pub const fn is_actionable(&self) -> bool {
        matches!(self, Self::Available { .. })
    }

    /// A line fit to show a person.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::UpToDate { current } => format!("{current} is the newest release"),
            Self::Available {
                version,
                tag,
                artifact,
                ..
            } => format!(
                "{tag} ({version}) is available: {} ({} bytes)",
                artifact.filename, artifact.size
            ),
            Self::Downgrade { current, offered } => format!(
                "refused: the manifest offers {offered}, which is older than {current}; \
                 a version never goes backwards"
            ),
            Self::WrongChannel {
                offered,
                configured,
            } => format!(
                "the manifest is for the {} channel; this client watches {}",
                offered.as_str(),
                configured.as_str()
            ),
            Self::WrongProduct { offered, expected } => {
                format!("the manifest is for {offered}, not {expected}")
            }
        }
    }
}

/// An update check.
#[derive(Debug, Clone)]
pub struct UpdateCheck {
    product: String,
    current: Version,
    current_released_at: Option<i64>,
    channel: UpdateChannel,
}

impl UpdateCheck {
    /// Set up a check for the running build.
    ///
    /// `current_released_at` is when the running build was published, if it is
    /// known. It is what breaks the tie when semver ordering disagrees with
    /// build order, which during the alpha line it does: `0.19.0` compares as
    /// ahead of `0.2.0` while `v0.2` is in fact the later build. Without it
    /// the updater is correct for `v1` onwards and stuck during the alpha.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidVersion`] if `current` is not a semantic version.
    pub fn new(
        product: impl Into<String>,
        current: &str,
        current_released_at: Option<i64>,
        channel: UpdateChannel,
    ) -> Result<Self> {
        Ok(Self {
            product: product.into(),
            current: Version::parse(current)?,
            current_released_at,
            channel,
        })
    }

    /// Verify a manifest and decide what it means.
    ///
    /// Verification comes first: an unsigned or wrongly signed manifest
    /// produces an error, never a decision. A `WrongChannel` answer about a
    /// document nobody can vouch for would be a statement about a stranger's
    /// opinion.
    ///
    /// # Errors
    ///
    /// [`Error::SignatureMissing`] when the manifest is unsigned, or whatever
    /// [`TrustStore::verify`] reports.
    pub fn evaluate(
        &self,
        manifest: &ReleaseManifest,
        trust: &TrustStore,
        build: BuildProfile,
        now: i64,
    ) -> Result<UpdateDecision> {
        manifest.validate()?;

        let envelope = manifest
            .signature
            .as_ref()
            .ok_or_else(|| Error::SignatureMissing(manifest.product.clone()))?;
        let subject = manifest.signing_subject()?;
        trust.verify(envelope, &subject, Artefact::Release, build, now)?;

        if manifest.product != self.product {
            return Ok(UpdateDecision::WrongProduct {
                offered: manifest.product.clone(),
                expected: self.product.clone(),
            });
        }
        if manifest.channel != self.channel {
            return Ok(UpdateDecision::WrongChannel {
                offered: manifest.channel,
                configured: self.channel,
            });
        }

        let offered = manifest.parsed_version()?;
        if offered == self.current {
            return Ok(UpdateDecision::UpToDate {
                current: self.current.to_string(),
            });
        }

        // Which is newer. Semver says one thing; during the alpha the release
        // dates say another, and the dates are right -- see the module docs.
        let newer = match (self.current_released_at, manifest.released_at_unix()) {
            (Some(current_at), Ok(offered_at)) if offered_at != current_at => {
                offered_at > current_at
            }
            _ => offered > self.current,
        };

        if !newer {
            return Ok(UpdateDecision::Downgrade {
                current: self.current.to_string(),
                offered: offered.to_string(),
            });
        }

        let platform =
            crate::module::Platform::host().ok_or_else(|| Error::NoArtifactForPlatform {
                version: manifest.version.clone(),
                platform: "unknown".to_owned(),
                arch: "unknown".to_owned(),
            })?;
        let arch = Arch::host().ok_or_else(|| Error::NoArtifactForPlatform {
            version: manifest.version.clone(),
            platform: platform.as_str().to_owned(),
            arch: "unknown".to_owned(),
        })?;
        let artifact = manifest.artifact_for(platform, arch)?.clone();

        Ok(UpdateDecision::Available {
            version: offered.to_string(),
            tag: manifest.tag.clone(),
            artifact,
            notes_url: manifest.notes_url.clone(),
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::{
        module::{Platform, SignatureAlgorithm},
        signature::{KeyPurpose, TrustedKey},
    };
    use base64::Engine as _;

    const TEST_SECRET: [u8; 32] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ];
    const NOW: i64 = 1_780_000_000;
    const PRODUCT: &str = "eon-stream";

    fn signing_key() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&TEST_SECRET)
    }

    fn trust(purpose: KeyPurpose) -> TrustStore {
        TrustStore::from_keys(vec![TrustedKey {
            key_id: format!("{}-2026-a", purpose.as_str()),
            purpose,
            public_key: base64::engine::general_purpose::STANDARD
                .encode(signing_key().verifying_key().to_bytes()),
            not_before: "2026-01-01T00:00:00Z".to_owned(),
            not_after: "2027-01-01T00:00:00Z".to_owned(),
            comment: None,
        }])
    }

    fn payload() -> Vec<u8> {
        b"a pretend windows executable".to_vec()
    }

    fn artifact() -> Artifact {
        let bytes = payload();
        Artifact {
            // The tests run on whatever this machine is, so the artefact is
            // built for the host: a release with nothing for this platform is
            // a different case, and has its own test.
            platform: Platform::host().unwrap_or(Platform::Windows),
            arch: Arch::host().unwrap_or(Arch::X86_64),
            filename: "eon-stream-v0.12-windows-x86_64.exe".to_owned(),
            size: bytes.len() as u64,
            sha256: content_hash(&bytes),
            url: "https://example.org/eon-stream-v0.12-windows-x86_64.exe".to_owned(),
        }
    }

    fn manifest(version: &str, tag: &str, released_at: i64) -> ReleaseManifest {
        ReleaseManifest {
            schema_version: 0,
            product: PRODUCT.to_owned(),
            channel: UpdateChannel::Alpha,
            version: version.to_owned(),
            tag: tag.to_owned(),
            released_at: crate::revocation::timestamp(released_at),
            notes_url: Some("https://example.org/notes".to_owned()),
            artifacts: vec![artifact()],
            signature: None,
        }
    }

    fn sign(mut manifest: ReleaseManifest, key_id: &str) -> ReleaseManifest {
        use ed25519_dalek::Signer as _;
        let subject = manifest.signing_subject().unwrap();
        let signature = signing_key().sign(&subject.canonical_bytes());
        manifest.signature = Some(SignatureEnvelope {
            algorithm: SignatureAlgorithm::Ed25519,
            key_id: key_id.to_owned(),
            value: base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()),
            signed_at: None,
        });
        manifest
    }

    fn check(current: &str, released_at: Option<i64>) -> UpdateCheck {
        UpdateCheck::new(PRODUCT, current, released_at, UpdateChannel::Alpha).unwrap()
    }

    #[test]
    fn a_newer_release_is_offered_with_the_file_for_this_machine() {
        let manifest = sign(manifest("0.12.0-alpha", "v0.12", NOW), "release-2026-a");
        let decision = check("0.11.0-alpha", Some(NOW - 86_400))
            .evaluate(
                &manifest,
                &trust(KeyPurpose::Release),
                BuildProfile::Stream,
                NOW,
            )
            .unwrap();
        match decision {
            UpdateDecision::Available {
                version,
                tag,
                artifact,
                notes_url,
            } => {
                assert_eq!(version, "0.12.0-alpha");
                assert_eq!(tag, "v0.12");
                assert_eq!(artifact.size as usize, payload().len());
                assert!(notes_url.is_some());
            }
            other => panic!("expected an available update, got {other:?}"),
        }
    }

    #[test]
    fn an_unsigned_manifest_is_an_error_not_a_decision() {
        // An unsigned manifest is not an update of unknown provenance, it is a
        // stranger choosing which binary you run.
        let manifest = manifest("0.12.0-alpha", "v0.12", NOW);
        assert!(matches!(
            check("0.11.0-alpha", None).evaluate(
                &manifest,
                &trust(KeyPurpose::Release),
                BuildProfile::Stream,
                NOW
            ),
            Err(Error::SignatureMissing(_))
        ));
    }

    #[test]
    fn a_module_key_cannot_sign_a_release_manifest() {
        let manifest = sign(manifest("0.12.0-alpha", "v0.12", NOW), "module-2026-a");
        assert!(check("0.11.0-alpha", None)
            .evaluate(
                &manifest,
                &trust(KeyPurpose::Module),
                BuildProfile::Stream,
                NOW
            )
            .is_err());
    }

    #[test]
    fn a_manifest_edited_after_signing_does_not_verify() {
        let mut manifest = sign(manifest("0.12.0-alpha", "v0.12", NOW), "release-2026-a");
        // Repoint the download. The signature covers the whole manifest, so
        // this is exactly what it is there to catch.
        manifest.artifacts[0].url = "https://elsewhere.example/evil.exe".to_owned();
        assert!(check("0.11.0-alpha", None)
            .evaluate(
                &manifest,
                &trust(KeyPurpose::Release),
                BuildProfile::Stream,
                NOW
            )
            .is_err());
    }

    #[test]
    fn a_replayed_older_manifest_is_a_reported_refusal() {
        // madde 39. The naive check is "offered != current", which accepts a
        // downgrade -- and a downgrade is how a patched vulnerability comes
        // back.
        let old = sign(
            manifest("0.9.0-alpha", "v0.9", NOW - 30 * 86_400),
            "release-2026-a",
        );
        let decision = check("0.11.0-alpha", Some(NOW - 86_400))
            .evaluate(&old, &trust(KeyPurpose::Release), BuildProfile::Stream, NOW)
            .unwrap();
        match &decision {
            UpdateDecision::Downgrade { current, offered } => {
                assert_eq!(current, "0.11.0-alpha");
                assert_eq!(offered, "0.9.0-alpha");
            }
            other => panic!("expected a downgrade refusal, got {other:?}"),
        }
        assert!(!decision.is_actionable());
        assert!(decision.describe().contains("never goes backwards"));
    }

    #[test]
    fn the_alpha_counter_updates_even_though_semver_disagrees() {
        // v0.19 is the twentieth alpha; v0.2 is the twenty-first. Semver reads
        // 0.19.0 as ahead of 0.2.0, so a client trusting semver alone would
        // call the newer build a downgrade and never update again.
        let newer = sign(manifest("0.2.0-alpha", "v0.2", NOW), "release-2026-a");
        let decision = check("0.19.0-alpha", Some(NOW - 7 * 86_400))
            .evaluate(
                &newer,
                &trust(KeyPurpose::Release),
                BuildProfile::Stream,
                NOW,
            )
            .unwrap();
        assert!(
            matches!(decision, UpdateDecision::Available { ref tag, .. } if tag == "v0.2"),
            "{decision:?}"
        );

        // And the protection still holds in the other direction: an older
        // build is refused even when semver would call it newer.
        let older = sign(
            manifest("0.19.0-alpha", "v0.19", NOW - 7 * 86_400),
            "release-2026-a",
        );
        let decision = check("0.2.0-alpha", Some(NOW))
            .evaluate(
                &older,
                &trust(KeyPurpose::Release),
                BuildProfile::Stream,
                NOW,
            )
            .unwrap();
        assert!(
            matches!(decision, UpdateDecision::Downgrade { .. }),
            "{decision:?}"
        );
    }

    #[test]
    fn without_a_release_date_it_falls_back_to_semver() {
        // Which is correct from v1 onwards, and is all a client has when it
        // does not know when it was built.
        let manifest = sign(manifest("1.1.0", "v1.1", NOW), "release-2026-a");
        let decision = UpdateCheck::new(PRODUCT, "1.0.0", None, UpdateChannel::Alpha)
            .unwrap()
            .evaluate(
                &manifest,
                &trust(KeyPurpose::Release),
                BuildProfile::Stream,
                NOW,
            )
            .unwrap();
        assert!(decision.is_actionable(), "{decision:?}");
    }

    #[test]
    fn the_same_version_is_up_to_date() {
        let manifest = sign(manifest("0.12.0-alpha", "v0.12", NOW), "release-2026-a");
        let decision = check("0.12.0-alpha", Some(NOW))
            .evaluate(
                &manifest,
                &trust(KeyPurpose::Release),
                BuildProfile::Stream,
                NOW,
            )
            .unwrap();
        assert!(matches!(decision, UpdateDecision::UpToDate { .. }));
    }

    #[test]
    fn another_channel_and_another_product_are_both_reported() {
        let mut other_channel = manifest("0.12.0-alpha", "v0.12", NOW);
        other_channel.channel = UpdateChannel::Stable;
        let decision = check("0.11.0-alpha", None)
            .evaluate(
                &sign(other_channel, "release-2026-a"),
                &trust(KeyPurpose::Release),
                BuildProfile::Stream,
                NOW,
            )
            .unwrap();
        assert!(matches!(decision, UpdateDecision::WrongChannel { .. }));

        let mut other_product = manifest("0.12.0-alpha", "v0.12", NOW);
        other_product.product = "eon-edu".to_owned();
        let decision = check("0.11.0-alpha", None)
            .evaluate(
                &sign(other_product, "release-2026-a"),
                &trust(KeyPurpose::Release),
                BuildProfile::Stream,
                NOW,
            )
            .unwrap();
        assert!(matches!(decision, UpdateDecision::WrongProduct { .. }));
    }

    #[test]
    fn the_artefact_hash_is_checked_against_the_signed_manifest() {
        let artifact = artifact();
        artifact.verify(&payload()).unwrap();

        // Tampered content.
        assert!(matches!(
            artifact.verify(b"a different pretend windows executable!"),
            Err(Error::InvalidReleaseManifest(_) | Error::ContentHashMismatch { .. })
        ));
    }

    #[test]
    fn a_size_mismatch_is_reported_separately_from_a_hash_mismatch() {
        // Almost every size mismatch is a truncated download, and almost no
        // hash mismatch is. Saying which saves an hour.
        let artifact = artifact();
        let truncated = &payload()[..5];
        let err = artifact.verify(truncated).unwrap_err().to_string();
        assert!(err.contains("bytes"), "{err}");

        let mut same_size = payload();
        let last = same_size.len() - 1;
        same_size[last] ^= 0xff;
        assert!(matches!(
            artifact.verify(&same_size),
            Err(Error::ContentHashMismatch { .. })
        ));
    }

    #[test]
    fn a_release_with_nothing_for_this_machine_says_so() {
        let mut manifest = manifest("0.12.0-alpha", "v0.12", NOW);
        // An architecture this test is certainly not running on.
        manifest.artifacts[0].arch = match Arch::host() {
            Some(Arch::X86_64) => Arch::Aarch64,
            _ => Arch::X86_64,
        };
        let result = check("0.11.0-alpha", Some(NOW - 86_400)).evaluate(
            &sign(manifest, "release-2026-a"),
            &trust(KeyPurpose::Release),
            BuildProfile::Stream,
            NOW,
        );
        assert!(matches!(result, Err(Error::NoArtifactForPlatform { .. })));
    }

    #[test]
    fn a_plain_http_download_url_is_refused() {
        let mut manifest = manifest("0.12.0-alpha", "v0.12", NOW);
        manifest.artifacts[0].url = "http://example.org/x.exe".to_owned();
        let err = manifest.validate().unwrap_err().to_string();
        assert!(err.contains("https"), "{err}");
    }

    #[test]
    fn a_filename_cannot_carry_a_path() {
        // The host joins this onto a directory.
        for hostile in [
            "../../autostart.exe",
            "/etc/cron.d/x",
            "C:\\windows\\x.exe",
            ".hidden",
            "",
        ] {
            let mut manifest = manifest("0.12.0-alpha", "v0.12", NOW);
            manifest.artifacts[0].filename = hostile.to_owned();
            assert!(manifest.validate().is_err(), "{hostile} should be refused");
        }
    }

    #[test]
    fn a_malformed_manifest_is_refused() {
        let mut empty = manifest("0.12.0-alpha", "v0.12", NOW);
        empty.artifacts.clear();
        assert!(empty.validate().is_err());

        let mut short_hash = manifest("0.12.0-alpha", "v0.12", NOW);
        short_hash.artifacts[0].sha256 = "abc".to_owned();
        assert!(short_hash.validate().is_err());

        let mut zero_size = manifest("0.12.0-alpha", "v0.12", NOW);
        zero_size.artifacts[0].size = 0;
        assert!(zero_size.validate().is_err());

        let mut bad_version = manifest("0.12", "v0.12", NOW);
        bad_version.version = "0.12".to_owned();
        assert!(bad_version.validate().is_err());
    }

    #[test]
    fn an_unknown_key_in_a_manifest_does_not_parse() {
        let json = br#"{"schemaVersion":0,"product":"eon-stream","channel":"alpha",
            "version":"0.12.0-alpha","tag":"v0.12","releasedAt":"2026-10-01T00:00:00Z",
            "artifacts":[],"installSilently":true}"#;
        assert!(ReleaseManifest::parse(json).is_err());
    }

    #[test]
    fn a_manifest_round_trips_through_json() {
        let manifest = sign(manifest("0.12.0-alpha", "v0.12", NOW), "release-2026-a");
        let bytes = serde_json::to_vec(&manifest).unwrap();
        assert_eq!(ReleaseManifest::parse(&bytes).unwrap(), manifest);
    }
}
