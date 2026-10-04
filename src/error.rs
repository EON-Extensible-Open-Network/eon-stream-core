// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 EON contributors
//
// Additional permission under GNU GPL version 3 section 7:
// see LICENSE-EXCEPTION.md (EON Module ABI Exception 1.0).

//! Errors surfaced to the host application.
//!
//! Every variant is written so the host can show it to a person without
//! translating it first, and so that one failing addon is always identifiable:
//! an error that cannot name its addon cannot be reported usefully.

use std::fmt;

/// The result type used throughout this crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Anything that can go wrong while talking to an addon.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The string the user supplied is not a usable addon address.
    #[error("not a usable addon address: {0}")]
    InvalidAddress(String),

    /// The addon answered, but not with success.
    #[error("addon returned HTTP {status}")]
    HttpStatus {
        /// The status code the addon returned.
        status: u16,
    },

    /// The request never completed: DNS, TLS, timeout, connection reset.
    #[error("could not reach the addon: {message}")]
    Transport {
        /// What the transport reported. Never contains the addon URL, which may
        /// carry credentials in its configuration path.
        message: String,
    },

    /// The addon answered with something that is not the JSON we expect.
    #[error("addon sent malformed JSON: {message}")]
    MalformedJson {
        /// The parser's complaint, with position information kept.
        message: String,
    },

    /// The manifest parsed but does not describe a usable addon.
    #[error("addon manifest is not usable: {0}")]
    InvalidManifest(String),

    /// The addon declares an addon-API major version this build does not
    /// implement. Refusing loudly beats failing obscurely later (madde 5).
    #[error("addon targets addon-API major version {wanted}, this build implements {ours}")]
    UnsupportedApiVersion {
        /// What the addon asked for.
        wanted: u32,
        /// What this build provides.
        ours: u32,
    },

    /// The addon's manifest does not declare the resource being requested, so
    /// the request was never sent.
    #[error("addon '{addon}' does not serve {resource} for type '{content_type}'")]
    ResourceNotOffered {
        /// Identifier of the addon that was asked.
        addon: String,
        /// The resource name, for example `catalog` or `stream`.
        resource: &'static str,
        /// The content type that was requested.
        content_type: String,
    },

    /// The response was larger than the configured cap. A slow or enormous
    /// addon must degrade itself, never the application.
    #[error("addon response exceeded the {limit} byte limit")]
    ResponseTooLarge {
        /// The cap that was exceeded, in bytes.
        limit: usize,
    },

    /// An addon with this identifier is already installed.
    #[error("addon '{0}' is already installed")]
    AlreadyInstalled(String),

    /// No installed addon carries this identifier.
    #[error("no installed addon with id '{0}'")]
    NotInstalled(String),

    /// Reading or writing the stored addon list failed.
    #[error("could not read the stored addon list: {message}")]
    Storage {
        /// What went wrong.
        message: String,
    },

    // ---------------------------------------------------------- versions
    /// A version string is not a semantic version.
    #[error("not a semantic version: {0}")]
    InvalidVersion(String),

    /// A dependency range is not npm range syntax, or uses a part of it this
    /// build does not implement.
    #[error("not a usable version range: {0}")]
    InvalidVersionRange(String),

    // ---------------------------------------------------------- modules
    /// The module manifest parsed but does not describe a usable module.
    #[error("module manifest is not usable: {0}")]
    InvalidModuleManifest(String),

    /// The module's declared API range excludes this build's module API
    /// version. Said plainly rather than failing obscurely later (madde 5).
    #[error("module '{module}' targets module API {wanted}, this build provides {ours}")]
    UnsupportedModuleApi {
        /// Identifier of the module that was offered.
        module: String,
        /// The range the module declared.
        wanted: String,
        /// The module API version this build implements.
        ours: String,
    },

    /// The module asks for a runtime this build will not execute. In v1 a
    /// third-party module is declarative only: there is no sandbox yet, and a
    /// security claim without one would not be honest (madde 4).
    #[error("module '{module}' needs the {runtime} runtime, which this build does not execute")]
    ModuleRuntimeNotSupported {
        /// Identifier of the module that was offered.
        module: String,
        /// The runtime it asked for.
        runtime: &'static str,
    },

    /// The module does not declare this build profile. An Edu build loads only
    /// Edu modules (madde 22).
    #[error("module '{module}' is not built for the {build} profile")]
    ModuleNotAllowedInBuild {
        /// Identifier of the module that was offered.
        module: String,
        /// The profile of the running build.
        build: &'static str,
    },

    /// A module with this identifier is already installed.
    #[error("module '{0}' is already installed")]
    ModuleAlreadyInstalled(String),

    /// No installed module carries this identifier.
    #[error("no installed module with id '{0}'")]
    ModuleNotInstalled(String),

    /// The offered module is not newer than the installed one. A version never
    /// goes backwards (madde 39): accepting an older build is how a fixed
    /// vulnerability gets reintroduced.
    #[error("module '{module}' is installed at {installed}; {offered} is not newer")]
    ModuleDowngrade {
        /// Identifier of the module.
        module: String,
        /// The version currently installed.
        installed: String,
        /// The version that was offered.
        offered: String,
    },

    /// A required dependency is not installed and was not offered alongside.
    #[error("module '{module}' needs '{dependency}' {range}, which is not installed")]
    MissingDependency {
        /// The module that has the dependency.
        module: String,
        /// Identifier of the missing module.
        dependency: String,
        /// The range that was asked for.
        range: String,
    },

    /// Dependencies form a cycle, so no load order exists.
    #[error("module dependencies form a cycle: {0}")]
    DependencyCycle(String),

    // ---------------------------------------------------------- signatures
    /// Nothing the client installs is unsigned.
    #[error("module '{0}' carries no signature")]
    SignatureMissing(String),

    /// The signature is present and does not verify.
    #[error("signature does not verify: {0}")]
    SignatureInvalid(String),

    /// The signature names a key this build does not trust.
    #[error("signature was made with key '{0}', which is not in the trust set")]
    UnknownSigningKey(String),

    /// The key is known but outside its validity window, or is the wrong kind
    /// of key for what it signed.
    #[error("signing key '{key_id}' is not usable here: {reason}")]
    KeyNotUsable {
        /// Identifier of the key.
        key_id: String,
        /// Why it was refused.
        reason: String,
    },

    /// Every key in the trust set has expired. A client with a stale trust set
    /// refuses rather than silently accepting anything.
    #[error("the trust set is stale: every key expired, the newest on {newest_expiry}")]
    TrustSetStale {
        /// When the last key to expire did so, as an RFC 3339 timestamp.
        newest_expiry: String,
    },

    /// The content does not hash to what the signature was made over.
    #[error("content hash mismatch: signature covers {expected}, content hashes to {actual}")]
    ContentHashMismatch {
        /// The hash the signature binds to.
        expected: String,
        /// The hash of the bytes actually supplied.
        actual: String,
    },

    /// The signature is valid but binds to a different artefact.
    #[error("signature is valid but covers {0}")]
    SubjectMismatch(String),

    /// This exact module version has been revoked.
    #[error("module '{id}' {version} is revoked ({reason})")]
    ModuleRevoked {
        /// Identifier of the module.
        id: String,
        /// The revoked version.
        version: String,
        /// Why it was revoked, from the enumerated reasons.
        reason: String,
        /// Advisory link, when the list carried one.
        advisory: Option<String>,
    },

    /// The key that signed this is revoked, which revokes everything it
    /// signed unless a newer valid signature exists.
    #[error("signing key '{key_id}' is revoked ({reason})")]
    SigningKeyRevoked {
        /// Identifier of the revoked key.
        key_id: String,
        /// Why it was revoked.
        reason: String,
    },

    /// The revocation list parsed but is not usable.
    #[error("revocation list is not usable: {0}")]
    InvalidRevocationList(String),

    /// A revocation list older than the one already held was offered. An
    /// attacker who can replay an old list must not be able to un-revoke.
    #[error("revocation list is older than the one held ({offered} < {held})")]
    RevocationRollback {
        /// `issuedAt` of the list that was offered.
        offered: String,
        /// `issuedAt` of the list currently held.
        held: String,
    },

    // ---------------------------------------------------------- themes etc.
    /// A theme document is not usable. A theme carries no code, ever, so an
    /// unrecognised key is an error and not an extension point (madde 4).
    #[error("theme is not usable: {0}")]
    InvalidTheme(String),

    /// Stored settings could not be read. A typo in a key is reported rather
    /// than ignored: silently dropping a setting the user wrote is worse.
    #[error("settings are not usable: {0}")]
    InvalidSettings(String),

    /// A release manifest is not usable.
    #[error("release manifest is not usable: {0}")]
    InvalidReleaseManifest(String),

    /// The release carries nothing for this platform.
    #[error("release {version} has no artefact for {platform}/{arch}")]
    NoArtifactForPlatform {
        /// The release version that was checked.
        version: String,
        /// Operating system that was asked for.
        platform: String,
        /// CPU architecture that was asked for.
        arch: String,
    },
}

/// One addon's failure inside an operation that spans several addons.
///
/// The resolver never lets a single bad addon empty a merged result
/// (madde 1): it collects failures beside the successes, and the host decides
/// what to show. The addon is identified by id and name — never by URL.
#[derive(Debug)]
pub struct AddonFailure {
    /// Identifier of the addon that failed.
    pub addon_id: String,
    /// Display name of the addon that failed.
    pub addon_name: String,
    /// What went wrong.
    pub error: Error,
}

impl fmt::Display for AddonFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({}): {}", self.addon_name, self.addon_id, self.error)
    }
}
