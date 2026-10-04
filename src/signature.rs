// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 EON contributors
//
// Additional permission under GNU GPL version 3 section 7:
// see LICENSE-EXCEPTION.md (EON Module ABI Exception 1.0).

//! Signature verification and the trust set.
//!
//! This crate **verifies and never signs**. Signing happens on an air-gapped
//! machine with the root key on a hardware token (see
//! `eon-stream-spec/docs/signing-and-revocation.md`); a client that can also
//! sign is a client whose compromise produces valid artefacts. The dependency
//! is configured to match: no key generation, no signing half.
//!
//! ## What a signature binds to
//!
//! A detached envelope over a **subject**: id, version and content hash
//! together. Binding all three is what makes a signature non-transferable —
//! lift it onto another version and the subject no longer matches — and it is
//! also what makes per-version revocation possible at all.
//!
//! The verifier never takes the subject from the envelope. It reconstructs it
//! from the manifest it read and the hash it computed itself, so a forged
//! subject field has nothing to attach to.
//!
//! ## Canonical serialisation — JCS, now pinned
//!
//! The spec listed this as open with JCS (RFC 8785) as the leading candidate,
//! and warned that leaving it open past the first real signature produces
//! signatures that verify in one client and fail in another. So it is pinned
//! here and in the spec: **the signed bytes are the JCS serialisation of the
//! subject object.**
//!
//! JCS over this object is small enough to implement correctly in one
//! function: three string members, keys sorted by UTF-16 code unit, no
//! whitespace, minimal string escapes. The full generality of JCS — number
//! formatting, nested containers — never arises, because the subject is fixed
//! by the contract. That is the reason the subject is fixed by the contract.
//!
//! ## Trust is a set, not a key
//!
//! Clients trust several keys at once so rotation locks nobody out: the new
//! key ships in a release, both are valid during an overlap, the old one
//! expires. The consequence that needs care is the other direction — a client
//! whose whole trust set has expired must **refuse and say the trust data is
//! stale**, never fall back to accepting whatever it is given.

use std::collections::BTreeMap;

use base64::Engine as _;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{
    error::{Error, Result},
    module::{BuildProfile, SignatureAlgorithm, SignatureEnvelope},
    time::{format_rfc3339, parse_rfc3339},
};

/// What a key is allowed to sign.
///
/// The Edu key is deliberately separate from the EON Stream module key
/// (madde 22). It is the enforcement behind "the open marketplace is not
/// merely hidden from an Edu build, it is absent": an Edu build trusts the Edu
/// key only, so a module from the open marketplace does not fail a policy
/// check — it fails signature verification, which no setting can turn off.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyPurpose {
    /// Signs application releases.
    Release,
    /// Signs first-party EON Stream modules.
    Module,
    /// Signs EON Edu modules and Edu releases.
    Edu,
    /// Generated per institution, signs that institution's own catalogue and
    /// packages. The project never holds one and cannot sign on an
    /// institution's behalf.
    Institution,
}

impl KeyPurpose {
    /// The identifier as it appears in a trust set.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Release => "release",
            Self::Module => "module",
            Self::Edu => "edu",
            Self::Institution => "institution",
        }
    }
}

/// What is being verified, which decides which purposes are acceptable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Artefact {
    /// A module package.
    Module,
    /// An application release.
    Release,
    /// A revocation list.
    Revocation,
}

impl Artefact {
    /// Purposes that may sign this artefact in `build`.
    ///
    /// An Edu build accepts the Edu key and nothing else, for either kind of
    /// artefact. A Stream build never accepts the Edu key: the separation runs
    /// both ways, so an Edu-signed module cannot be installed into an open
    /// build either.
    #[must_use]
    pub fn acceptable_purposes(self, build: BuildProfile) -> &'static [KeyPurpose] {
        match (self, build) {
            (_, BuildProfile::Edu) => &[KeyPurpose::Edu],
            (Self::Module, BuildProfile::Stream) => &[KeyPurpose::Module],
            // A revocation list is a release-key artefact: it has to be
            // publishable at 3am without reaching for the module key.
            (Self::Release | Self::Revocation, BuildProfile::Stream) => &[KeyPurpose::Release],
        }
    }
}

/// What a signature covers: an exact module or release, at an exact version,
/// with exactly these bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Subject {
    /// Identifier of the signed thing.
    pub id: String,
    /// Its version.
    pub version: String,
    /// Lowercase hex SHA-256 of its contents.
    pub sha256: String,
}

impl Subject {
    /// Build a subject from an identity and the bytes themselves.
    #[must_use]
    pub fn of(id: impl Into<String>, version: impl Into<String>, content: &[u8]) -> Self {
        Self {
            id: id.into(),
            version: version.into(),
            sha256: content_hash(content),
        }
    }

    /// The exact bytes a signature is made over: the JCS serialisation of this
    /// object.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        // JCS: members sorted by key, no insignificant whitespace. The three
        // keys sort as id < sha256 < version, and a BTreeMap gives that
        // ordering for free -- but it is written out here rather than relied
        // on, because the ordering is part of the contract and a reader should
        // be able to see it.
        let mut json = String::from("{\"id\":");
        json.push_str(&json_string(&self.id));
        json.push_str(",\"sha256\":");
        json.push_str(&json_string(&self.sha256));
        json.push_str(",\"version\":");
        json.push_str(&json_string(&self.version));
        json.push('}');
        json.into_bytes()
    }

    /// A one-line description for an error message.
    #[must_use]
    pub fn describe(&self) -> String {
        format!("{} {} (sha256 {})", self.id, self.version, self.sha256)
    }
}

/// A JSON string literal, escaped as RFC 8785 requires.
///
/// The short escapes where they exist, `\u00xx` for the other control
/// characters, and nothing else — notably **not** `\u` escapes for non-ASCII,
/// which JCS writes as UTF-8. Getting that backwards is the classic JCS
/// mistake, so there is a test for a module id that is pure ASCII and a theme
/// name that is not.
fn json_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c < '\u{20}' => {
                use std::fmt::Write as _;
                // `write!` rather than `push_str(&format!(..))`: no
                // intermediate allocation, and writing to a `String` cannot
                // fail, so discarding the `Result` loses nothing.
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Lowercase hex SHA-256 of `content`.
#[must_use]
pub fn content_hash(content: &[u8]) -> String {
    let digest = Sha256::digest(content);
    let mut hex = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

/// A key this build trusts, and the window in which it is trusted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedKey {
    /// Identifier a signature names.
    #[serde(rename = "keyId")]
    pub key_id: String,
    /// What the key may sign.
    pub purpose: KeyPurpose,
    /// Base64 Ed25519 public key, 32 bytes.
    #[serde(rename = "publicKey")]
    pub public_key: String,
    /// Start of the validity window, RFC 3339.
    #[serde(rename = "notBefore")]
    pub not_before: String,
    /// End of the validity window, RFC 3339.
    #[serde(rename = "notAfter")]
    pub not_after: String,
    /// Human-readable note: whose key it is, where it lives.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

impl TrustedKey {
    /// Decode the public key.
    ///
    /// # Errors
    ///
    /// [`Error::KeyNotUsable`] if it is not 32 base64 bytes, or is not a valid
    /// Ed25519 point.
    pub fn verifying_key(&self) -> Result<VerifyingKey> {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(self.public_key.trim())
            .map_err(|e| Error::KeyNotUsable {
                key_id: self.key_id.clone(),
                reason: format!("public key is not base64: {e}"),
            })?;
        let bytes: [u8; 32] = bytes.try_into().map_err(|_| Error::KeyNotUsable {
            key_id: self.key_id.clone(),
            reason: "public key is not 32 bytes".to_owned(),
        })?;
        VerifyingKey::from_bytes(&bytes).map_err(|e| Error::KeyNotUsable {
            key_id: self.key_id.clone(),
            reason: format!("public key is not a usable Ed25519 key: {e}"),
        })
    }

    /// The validity window as Unix seconds.
    fn window(&self) -> Result<(i64, i64)> {
        let not_before = parse_rfc3339(&self.not_before).map_err(|e| Error::KeyNotUsable {
            key_id: self.key_id.clone(),
            reason: format!("notBefore: {e}"),
        })?;
        let not_after = parse_rfc3339(&self.not_after).map_err(|e| Error::KeyNotUsable {
            key_id: self.key_id.clone(),
            reason: format!("notAfter: {e}"),
        })?;
        if not_after <= not_before {
            return Err(Error::KeyNotUsable {
                key_id: self.key_id.clone(),
                reason: "validity window ends before it starts".to_owned(),
            });
        }
        Ok((not_before, not_after))
    }

    /// Whether the key is inside its window at `now`.
    ///
    /// # Errors
    ///
    /// [`Error::KeyNotUsable`] if either timestamp is malformed.
    pub fn is_valid_at(&self, now: i64) -> Result<bool> {
        let (not_before, not_after) = self.window()?;
        Ok(now >= not_before && now < not_after)
    }
}

/// The keys a build trusts.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustStore {
    /// Schema version of the trust document.
    #[serde(rename = "schemaVersion")]
    pub schema_version: u32,
    /// Every key currently shipped, expired ones included — an expired key
    /// present in the set produces "this key expired on <date>", while one
    /// dropped from the set produces only "unknown key". The first is a
    /// diagnosis; the second is a mystery.
    pub keys: Vec<TrustedKey>,
}

/// How fresh the trust set is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustFreshness {
    /// At least one key is valid right now.
    Fresh,
    /// Every key has expired. The client refuses rather than accepting
    /// anything, and says why.
    Stale {
        /// When the last key to expire did so, RFC 3339.
        newest_expiry: String,
    },
    /// The set carries no keys at all.
    Empty,
}

impl TrustStore {
    /// Parse a trust document.
    ///
    /// # Errors
    ///
    /// [`Error::MalformedJson`] if the bytes are not the expected JSON, or
    /// [`Error::InvalidSettings`] if the schema version is one this build does
    /// not read.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let store: Self = serde_json::from_slice(bytes).map_err(|e| Error::MalformedJson {
            message: e.to_string(),
        })?;
        if store.schema_version != 0 {
            return Err(Error::InvalidSettings(format!(
                "trust set schemaVersion is {}, this build reads 0",
                store.schema_version
            )));
        }
        let mut ids: Vec<&str> = store.keys.iter().map(|k| k.key_id.as_str()).collect();
        ids.sort_unstable();
        let count = ids.len();
        ids.dedup();
        if ids.len() != count {
            return Err(Error::InvalidSettings(
                "the trust set lists one key id twice".to_owned(),
            ));
        }
        Ok(store)
    }

    /// An empty set, which trusts nothing and says so.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            schema_version: 0,
            keys: Vec::new(),
        }
    }

    /// Build a set from keys held in memory, for tests and for the
    /// institution case where keys are enrolled at runtime.
    #[must_use]
    pub fn from_keys(keys: Vec<TrustedKey>) -> Self {
        Self {
            schema_version: 0,
            keys,
        }
    }

    /// Whether anything in the set is usable at `now`.
    ///
    /// # Errors
    ///
    /// [`Error::KeyNotUsable`] if a key carries a malformed timestamp.
    pub fn freshness(&self, now: i64) -> Result<TrustFreshness> {
        if self.keys.is_empty() {
            return Ok(TrustFreshness::Empty);
        }
        let mut newest_expiry = i64::MIN;
        for key in &self.keys {
            if key.is_valid_at(now)? {
                return Ok(TrustFreshness::Fresh);
            }
            let (_, not_after) = key.window()?;
            newest_expiry = newest_expiry.max(not_after);
        }
        Ok(TrustFreshness::Stale {
            newest_expiry: format_rfc3339(newest_expiry),
        })
    }

    /// Verify `envelope` over `subject`.
    ///
    /// The caller passes the subject it built itself from the manifest and the
    /// bytes it hashed; nothing here reads a subject out of the envelope.
    ///
    /// # Errors
    ///
    /// In the order the checks run, so the first failure is the most
    /// informative one: [`Error::TrustSetStale`] when nothing in the set is
    /// usable, [`Error::UnknownSigningKey`] for a key not in the set,
    /// [`Error::KeyNotUsable`] when the key is outside its window or has the
    /// wrong purpose, and [`Error::SignatureInvalid`] when the bytes do not
    /// verify.
    pub fn verify(
        &self,
        envelope: &SignatureEnvelope,
        subject: &Subject,
        artefact: Artefact,
        build: BuildProfile,
        now: i64,
    ) -> Result<&TrustedKey> {
        // Order matters. A stale trust set has to be reported as a stale trust
        // set, not as "unknown key": an attacker who can keep a client from
        // updating should produce an alarming message, not a confusing one.
        match self.freshness(now)? {
            TrustFreshness::Fresh => {}
            TrustFreshness::Stale { newest_expiry } => {
                return Err(Error::TrustSetStale { newest_expiry })
            }
            TrustFreshness::Empty => {
                return Err(Error::TrustSetStale {
                    newest_expiry: "never: the trust set is empty".to_owned(),
                })
            }
        }

        let key = self
            .keys
            .iter()
            .find(|k| k.key_id == envelope.key_id)
            .ok_or_else(|| Error::UnknownSigningKey(envelope.key_id.clone()))?;

        if !key.is_valid_at(now)? {
            let (not_before, not_after) = key.window()?;
            return Err(Error::KeyNotUsable {
                key_id: key.key_id.clone(),
                reason: if now < not_before {
                    format!("not valid until {}", format_rfc3339(not_before))
                } else {
                    format!("expired on {}", format_rfc3339(not_after))
                },
            });
        }

        let acceptable = artefact.acceptable_purposes(build);
        if !acceptable.contains(&key.purpose) {
            return Err(Error::KeyNotUsable {
                key_id: key.key_id.clone(),
                reason: format!(
                    "it is a {} key; a {} build accepts {} here",
                    key.purpose.as_str(),
                    build.as_str(),
                    acceptable
                        .iter()
                        .map(|p| p.as_str())
                        .collect::<Vec<_>>()
                        .join(" or ")
                ),
            });
        }

        let SignatureAlgorithm::Ed25519 = envelope.algorithm;
        let raw = base64::engine::general_purpose::STANDARD
            .decode(envelope.value.trim())
            .map_err(|e| Error::SignatureInvalid(format!("value is not base64: {e}")))?;
        let raw: [u8; 64] = raw
            .try_into()
            .map_err(|_| Error::SignatureInvalid("value is not 64 bytes".to_owned()))?;
        let signature = Signature::from_bytes(&raw);

        key.verifying_key()?
            // `verify_strict` and not `verify`: it rejects small-order public
            // keys and non-canonical encodings, which is what closes the
            // signature-malleability hole where one artefact has two valid
            // signatures.
            .verify_strict(&subject.canonical_bytes(), &signature)
            .map_err(|_| {
                Error::SignatureInvalid(format!(
                    "key '{}' did not sign {}",
                    key.key_id,
                    subject.describe()
                ))
            })?;
        Ok(key)
    }

    /// Remove the keys a revocation list names, returning what was removed.
    ///
    /// Revoking a key revokes everything it signed, so this is applied to the
    /// trust set rather than checked per artefact.
    pub fn revoke_keys(&mut self, revoked: &BTreeMap<String, String>) -> Vec<(String, String)> {
        let mut removed = Vec::new();
        self.keys.retain(|key| match revoked.get(&key.key_id) {
            Some(reason) => {
                removed.push((key.key_id.clone(), reason.clone()));
                false
            }
            None => true,
        });
        removed
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    // A fixed key pair. The secret half is here because these tests have to
    // produce signatures and this crate deliberately cannot: the bytes below
    // were generated once, offline, and they sign nothing that exists.
    //
    // Ed25519 secret scalar, then the matching public key.
    const TEST_SECRET: [u8; 32] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ];

    fn signing_key() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&TEST_SECRET)
    }

    fn public_b64() -> String {
        base64::engine::general_purpose::STANDARD.encode(signing_key().verifying_key().to_bytes())
    }

    fn key(purpose: KeyPurpose) -> TrustedKey {
        TrustedKey {
            key_id: format!("{}-2026-a", purpose.as_str()),
            purpose,
            public_key: public_b64(),
            not_before: "2026-01-01T00:00:00Z".to_owned(),
            not_after: "2027-01-01T00:00:00Z".to_owned(),
            comment: None,
        }
    }

    fn sign(subject: &Subject, key_id: &str) -> SignatureEnvelope {
        use ed25519_dalek::Signer as _;
        let signature = signing_key().sign(&subject.canonical_bytes());
        SignatureEnvelope {
            algorithm: SignatureAlgorithm::Ed25519,
            key_id: key_id.to_owned(),
            value: base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()),
            signed_at: Some("2026-06-01T00:00:00Z".to_owned()),
        }
    }

    const NOW: i64 = 1_780_000_000; // mid-2026, inside the window above.

    #[test]
    fn canonical_bytes_are_jcs_with_sorted_keys() {
        let subject = Subject {
            id: "org.eon.stream.video".to_owned(),
            version: "1.2.0".to_owned(),
            sha256: "00".repeat(32),
        };
        let json = String::from_utf8(subject.canonical_bytes()).unwrap();
        assert_eq!(
            json,
            format!(
                "{{\"id\":\"org.eon.stream.video\",\"sha256\":\"{}\",\"version\":\"1.2.0\"}}",
                "00".repeat(32)
            )
        );
        // No whitespace anywhere: a single space would change every signature.
        assert!(!json.contains(' '));
    }

    #[test]
    fn jcs_writes_non_ascii_as_utf8_not_as_escapes() {
        // The classic JCS mistake is \u-escaping non-ASCII. RFC 8785 says
        // UTF-8. A Turkish module name is the case that catches it here.
        let subject = Subject {
            id: "community.example.gece".to_owned(),
            version: "1.0.0-şafak".to_owned(),
            sha256: "ab".repeat(32),
        };
        let json = String::from_utf8(subject.canonical_bytes()).unwrap();
        assert!(json.contains("şafak"), "{json}");
        assert!(!json.contains("\\u"), "{json}");
    }

    #[test]
    fn jcs_escapes_control_characters_the_short_way() {
        let subject = Subject {
            id: "a.b".to_owned(),
            version: "1.0.0".to_owned(),
            sha256: "x\n\t\"\\\u{1}".to_owned(),
        };
        let json = String::from_utf8(subject.canonical_bytes()).unwrap();
        // Assembled from a backslash char rather than written as a literal, so
        // the expectation is not itself an escape sequence a reader has to
        // decode twice to check.
        let bs = '\\';
        let expected = format!("x{bs}n{bs}t{bs}\"{bs}{bs}{bs}u0001");
        assert!(json.contains(&expected), "{json} lacks {expected}");
    }

    #[test]
    fn content_hash_is_lowercase_hex_sha256() {
        // The published SHA-256 of the empty string.
        assert_eq!(
            content_hash(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn a_good_signature_verifies() {
        let store = TrustStore::from_keys(vec![key(KeyPurpose::Module)]);
        let subject = Subject::of("org.eon.stream.video", "1.0.0", b"module bytes");
        let envelope = sign(&subject, "module-2026-a");
        let used = store
            .verify(
                &envelope,
                &subject,
                Artefact::Module,
                BuildProfile::Stream,
                NOW,
            )
            .unwrap();
        assert_eq!(used.key_id, "module-2026-a");
    }

    #[test]
    fn a_signature_does_not_transfer_to_another_version() {
        // The property the subject binding exists for: lift a valid signature
        // onto a different version and it stops verifying.
        let store = TrustStore::from_keys(vec![key(KeyPurpose::Module)]);
        let signed = Subject::of("org.eon.stream.video", "1.0.0", b"module bytes");
        let envelope = sign(&signed, "module-2026-a");

        let other_version = Subject::of("org.eon.stream.video", "1.0.1", b"module bytes");
        assert!(store
            .verify(
                &envelope,
                &other_version,
                Artefact::Module,
                BuildProfile::Stream,
                NOW
            )
            .is_err());

        let other_content = Subject::of("org.eon.stream.video", "1.0.0", b"tampered bytes");
        assert!(store
            .verify(
                &envelope,
                &other_content,
                Artefact::Module,
                BuildProfile::Stream,
                NOW
            )
            .is_err());
    }

    #[test]
    fn an_edu_build_does_not_trust_the_stream_module_key() {
        // madde 22, as a signature check rather than a policy flag.
        let store = TrustStore::from_keys(vec![key(KeyPurpose::Module)]);
        let subject = Subject::of("org.eon.stream.video", "1.0.0", b"bytes");
        let envelope = sign(&subject, "module-2026-a");
        let err = store
            .verify(
                &envelope,
                &subject,
                Artefact::Module,
                BuildProfile::Edu,
                NOW,
            )
            .unwrap_err();
        assert!(matches!(err, Error::KeyNotUsable { .. }), "{err}");
    }

    #[test]
    fn a_stream_build_does_not_trust_the_edu_key_either() {
        let store = TrustStore::from_keys(vec![key(KeyPurpose::Edu)]);
        let subject = Subject::of("org.eon.edu.tool", "1.0.0", b"bytes");
        let envelope = sign(&subject, "edu-2026-a");
        assert!(store
            .verify(
                &envelope,
                &subject,
                Artefact::Module,
                BuildProfile::Stream,
                NOW
            )
            .is_err());
    }

    #[test]
    fn a_module_key_cannot_sign_a_release() {
        let store = TrustStore::from_keys(vec![key(KeyPurpose::Module)]);
        let subject = Subject::of("eon-stream", "0.12.0", b"installer bytes");
        let envelope = sign(&subject, "module-2026-a");
        assert!(store
            .verify(
                &envelope,
                &subject,
                Artefact::Release,
                BuildProfile::Stream,
                NOW
            )
            .is_err());
    }

    #[test]
    fn an_expired_key_says_when_it_expired() {
        let mut k = key(KeyPurpose::Module);
        k.not_before = "2020-01-01T00:00:00Z".to_owned();
        k.not_after = "2021-01-01T00:00:00Z".to_owned();
        let store = TrustStore::from_keys(vec![k]);
        let subject = Subject::of("org.eon.stream.video", "1.0.0", b"bytes");
        let envelope = sign(&subject, "module-2026-a");
        // Everything has expired, so this is a stale trust set rather than a
        // key problem -- and that is the more useful thing to say.
        match store.verify(
            &envelope,
            &subject,
            Artefact::Module,
            BuildProfile::Stream,
            NOW,
        ) {
            Err(Error::TrustSetStale { newest_expiry }) => {
                assert!(newest_expiry.starts_with("2021-01-01"), "{newest_expiry}");
            }
            other => panic!("expected a stale trust set, got {other:?}"),
        }
    }

    #[test]
    fn one_expired_key_beside_a_valid_one_is_not_staleness() {
        let mut old = key(KeyPurpose::Module);
        old.key_id = "module-2025-a".to_owned();
        old.not_before = "2025-01-01T00:00:00Z".to_owned();
        old.not_after = "2026-01-01T00:00:00Z".to_owned();
        let store = TrustStore::from_keys(vec![old, key(KeyPurpose::Module)]);
        assert_eq!(store.freshness(NOW).unwrap(), TrustFreshness::Fresh);

        // Rotation overlap: a signature from the old key is refused by name,
        // and the new key keeps working.
        let subject = Subject::of("org.eon.stream.video", "1.0.0", b"bytes");
        let old_envelope = sign(&subject, "module-2025-a");
        assert!(matches!(
            store.verify(
                &old_envelope,
                &subject,
                Artefact::Module,
                BuildProfile::Stream,
                NOW
            ),
            Err(Error::KeyNotUsable { .. })
        ));
        assert!(store
            .verify(
                &sign(&subject, "module-2026-a"),
                &subject,
                Artefact::Module,
                BuildProfile::Stream,
                NOW
            )
            .is_ok());
    }

    #[test]
    fn an_empty_trust_set_accepts_nothing() {
        let store = TrustStore::empty();
        let subject = Subject::of("org.eon.stream.video", "1.0.0", b"bytes");
        let envelope = sign(&subject, "module-2026-a");
        assert!(matches!(
            store.verify(
                &envelope,
                &subject,
                Artefact::Module,
                BuildProfile::Stream,
                NOW
            ),
            Err(Error::TrustSetStale { .. })
        ));
        assert_eq!(store.freshness(NOW).unwrap(), TrustFreshness::Empty);
    }

    #[test]
    fn an_unknown_key_id_is_named() {
        let store = TrustStore::from_keys(vec![key(KeyPurpose::Module)]);
        let subject = Subject::of("org.eon.stream.video", "1.0.0", b"bytes");
        let mut envelope = sign(&subject, "module-2026-a");
        envelope.key_id = "someone-elses-key".to_owned();
        match store.verify(
            &envelope,
            &subject,
            Artefact::Module,
            BuildProfile::Stream,
            NOW,
        ) {
            Err(Error::UnknownSigningKey(id)) => assert_eq!(id, "someone-elses-key"),
            other => panic!("expected an unknown-key error, got {other:?}"),
        }
    }

    #[test]
    fn a_tampered_signature_does_not_verify() {
        let store = TrustStore::from_keys(vec![key(KeyPurpose::Module)]);
        let subject = Subject::of("org.eon.stream.video", "1.0.0", b"bytes");
        let mut envelope = sign(&subject, "module-2026-a");
        // Flip one base64 character.
        let mut value: Vec<char> = envelope.value.chars().collect();
        value[0] = if value[0] == 'A' { 'B' } else { 'A' };
        envelope.value = value.into_iter().collect();
        assert!(store
            .verify(
                &envelope,
                &subject,
                Artefact::Module,
                BuildProfile::Stream,
                NOW
            )
            .is_err());
    }

    #[test]
    fn a_wrong_length_signature_is_refused_before_any_crypto() {
        let store = TrustStore::from_keys(vec![key(KeyPurpose::Module)]);
        let subject = Subject::of("a.b", "1.0.0", b"bytes");
        let envelope = SignatureEnvelope {
            algorithm: SignatureAlgorithm::Ed25519,
            key_id: "module-2026-a".to_owned(),
            value: base64::engine::general_purpose::STANDARD.encode([0u8; 8]),
            signed_at: None,
        };
        assert!(store
            .verify(
                &envelope,
                &subject,
                Artefact::Module,
                BuildProfile::Stream,
                NOW
            )
            .is_err());
    }

    #[test]
    fn an_unknown_algorithm_does_not_parse() {
        // A verifier that skips signatures it does not understand verifies
        // nothing, so the algorithm is an enum and this is a parse error.
        let json = br#"{"algorithm":"rsa-pkcs1","keyId":"k","value":"AA=="}"#;
        assert!(serde_json::from_slice::<SignatureEnvelope>(json).is_err());
    }

    #[test]
    fn a_duplicate_key_id_in_the_trust_set_is_refused() {
        let json = serde_json::to_vec(&serde_json::json!({
            "schemaVersion": 0,
            "keys": [
                {"keyId": "k", "purpose": "module", "publicKey": public_b64(),
                 "notBefore": "2026-01-01T00:00:00Z", "notAfter": "2027-01-01T00:00:00Z"},
                {"keyId": "k", "purpose": "release", "publicKey": public_b64(),
                 "notBefore": "2026-01-01T00:00:00Z", "notAfter": "2027-01-01T00:00:00Z"}
            ]
        }))
        .unwrap();
        assert!(TrustStore::parse(&json).is_err());
    }

    #[test]
    fn revoking_a_key_removes_it_from_the_set() {
        let mut store = TrustStore::from_keys(vec![key(KeyPurpose::Module), key(KeyPurpose::Edu)]);
        let mut revoked = BTreeMap::new();
        revoked.insert("module-2026-a".to_owned(), "key-compromise".to_owned());
        let removed = store.revoke_keys(&revoked);
        assert_eq!(removed.len(), 1);
        assert_eq!(store.keys.len(), 1);
        assert_eq!(store.keys[0].key_id, "edu-2026-a");
    }

    #[test]
    fn an_inverted_validity_window_is_an_error_not_a_window() {
        let mut k = key(KeyPurpose::Module);
        k.not_after = k.not_before.clone();
        assert!(k.is_valid_at(NOW).is_err());
    }
}
