// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 EON contributors
//
// Additional permission under GNU GPL version 3 section 7:
// see LICENSE-EXCEPTION.md (EON Module ABI Exception 1.0).

//! Module manifests.
//!
//! A *module* is a part of EON Stream that can be installed and removed: a
//! viewer, a theme, a creator tool. The authoritative schema lives in
//! `eon-stream-spec` (`schemas/module-manifest.v0.schema.json`); this is its
//! Rust half, and the two are kept in step by a test that parses the spec's own
//! example documents, including the deliberately invalid ones.
//!
//! Unlike an *addon* manifest, a module manifest is **strict**: an
//! unrecognised key is an error. The reason is the opposite of the reason
//! addon manifests are lenient. An addon manifest comes from a third party over
//! HTTP and the goal is compatibility; a module manifest describes something
//! about to be installed on the user's machine, and a key nobody recognises is
//! either a typo in a permission name or an attempt to smuggle something past a
//! reader. Neither should be accepted quietly.
//!
//! First-party modules use this same schema and the same permission model as
//! third-party ones (madde 3). There is no privileged manifest form.

use serde::{Deserialize, Serialize};

use crate::{
    error::{Error, Result},
    semver::{Version, VersionRange},
};

/// Module API major version this build implements.
pub const MODULE_API_MAJOR: u32 = 0;

/// Module API minor version this build implements.
pub const MODULE_API_MINOR: u32 = 1;

/// Which class of module this is, deciding what host surfaces it may attach
/// to. A module declares exactly one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ModuleKind {
    /// Plays video.
    #[serde(rename = "viewer.video")]
    ViewerVideo,
    /// Plays audio.
    #[serde(rename = "viewer.music")]
    ViewerMusic,
    /// Opens documents and other files.
    #[serde(rename = "viewer.file")]
    ViewerFile,
    /// Opens material packages.
    #[serde(rename = "viewer.package")]
    ViewerPackage,
    /// Produces content rather than displaying it.
    #[serde(rename = "creator")]
    Creator,
    /// A marketplace front end.
    #[serde(rename = "marketplace")]
    Marketplace,
    /// Colour, type and layout only. Carries no code, ever.
    #[serde(rename = "theme")]
    Theme,
    /// Contributes interface surfaces.
    #[serde(rename = "ui")]
    Ui,
    /// An EON Edu teaching tool.
    #[serde(rename = "edu.tool")]
    EduTool,
    /// An EON Edu identity provider.
    #[serde(rename = "edu.identity")]
    EduIdentity,
}

impl ModuleKind {
    /// The identifier as it appears in a manifest.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ViewerVideo => "viewer.video",
            Self::ViewerMusic => "viewer.music",
            Self::ViewerFile => "viewer.file",
            Self::ViewerPackage => "viewer.package",
            Self::Creator => "creator",
            Self::Marketplace => "marketplace",
            Self::Theme => "theme",
            Self::Ui => "ui",
            Self::EduTool => "edu.tool",
            Self::EduIdentity => "edu.identity",
        }
    }

    /// Whether this kind only exists inside an EON Edu build.
    #[must_use]
    pub const fn is_edu_only(self) -> bool {
        matches!(self, Self::EduTool | Self::EduIdentity)
    }
}

/// How a module is executed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuntimeKind {
    /// No code at all: a JSON document the host interprets. The only runtime
    /// available to a third-party module in v1 (madde 4).
    #[serde(rename = "declarative")]
    Declarative,
    /// WebAssembly in a capability-gated sandbox. The intended home for
    /// code-executing modules; not implemented (madde 4).
    #[serde(rename = "wasm")]
    Wasm,
    /// Compiled into the client. Reserved for first-party modules.
    #[serde(rename = "native")]
    Native,
}

impl RuntimeKind {
    /// The identifier as it appears in a manifest.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Declarative => "declarative",
            Self::Wasm => "wasm",
            Self::Native => "native",
        }
    }
}

/// A capability a module asks the host for.
///
/// Each one maps to a host function the sandbox grants or withholds. Nothing is
/// granted implicitly, and the set is closed: a permission this build does not
/// know is a parse error, because "unknown permission, assumed harmless" is how
/// a permission system stops meaning anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Permission {
    /// Make outbound network requests.
    #[serde(rename = "net.fetch")]
    NetFetch,
    /// Keep its own local storage.
    #[serde(rename = "storage.local")]
    StorageLocal,
    /// Read files the user explicitly picked.
    #[serde(rename = "fs.read.userSelected")]
    FsReadUserSelected,
    /// Write into the downloads directory.
    #[serde(rename = "fs.write.downloads")]
    FsWriteDownloads,
    /// Control playback.
    #[serde(rename = "player.control")]
    PlayerControl,
    /// Read catalogue contents.
    #[serde(rename = "catalog.read")]
    CatalogRead,
    /// Read the installed addon list — **ids and names only**. A configured
    /// addon URL can carry credentials, so it never reaches a module.
    #[serde(rename = "addons.read")]
    AddonsRead,
    /// Draw an interface surface.
    #[serde(rename = "ui.surface")]
    UiSurface,
    /// Post a notification.
    #[serde(rename = "notifications.post")]
    NotificationsPost,
    /// Write to the clipboard.
    #[serde(rename = "clipboard.write")]
    ClipboardWrite,
}

impl Permission {
    /// The identifier as it appears in a manifest.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NetFetch => "net.fetch",
            Self::StorageLocal => "storage.local",
            Self::FsReadUserSelected => "fs.read.userSelected",
            Self::FsWriteDownloads => "fs.write.downloads",
            Self::PlayerControl => "player.control",
            Self::CatalogRead => "catalog.read",
            Self::AddonsRead => "addons.read",
            Self::UiSurface => "ui.surface",
            Self::NotificationsPost => "notifications.post",
            Self::ClipboardWrite => "clipboard.write",
        }
    }

    /// A one-line statement of what granting this allows, for the installation
    /// prompt. Keyed message text lives in [`crate::i18n`]; this is the key.
    #[must_use]
    pub const fn message_key(self) -> &'static str {
        match self {
            Self::NetFetch => "permission.net.fetch",
            Self::StorageLocal => "permission.storage.local",
            Self::FsReadUserSelected => "permission.fs.read.userSelected",
            Self::FsWriteDownloads => "permission.fs.write.downloads",
            Self::PlayerControl => "permission.player.control",
            Self::CatalogRead => "permission.catalog.read",
            Self::AddonsRead => "permission.addons.read",
            Self::UiSurface => "permission.ui.surface",
            Self::NotificationsPost => "permission.notifications.post",
            Self::ClipboardWrite => "permission.clipboard.write",
        }
    }
}

/// Which build may load a module.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BuildProfile {
    /// The open EON Stream build.
    #[serde(rename = "stream")]
    Stream,
    /// The institutional EON Edu build, which reaches no open marketplace and
    /// loads only Edu-signed modules (madde 22).
    #[serde(rename = "edu")]
    Edu,
}

impl BuildProfile {
    /// The identifier as it appears in a manifest.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Stream => "stream",
            Self::Edu => "edu",
        }
    }
}

/// An operating system a module supports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Platform {
    /// Microsoft Windows.
    Windows,
    /// Linux.
    Linux,
    /// macOS.
    Macos,
    /// Android.
    Android,
}

impl Platform {
    /// The platform this build is running on, or `None` on a target the
    /// manifest vocabulary has no word for.
    #[must_use]
    pub const fn host() -> Option<Self> {
        if cfg!(target_os = "windows") {
            Some(Self::Windows)
        } else if cfg!(target_os = "linux") {
            Some(Self::Linux)
        } else if cfg!(target_os = "macos") {
            Some(Self::Macos)
        } else if cfg!(target_os = "android") {
            Some(Self::Android)
        } else {
            None
        }
    }

    /// The identifier as it appears in a manifest.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Windows => "windows",
            Self::Linux => "linux",
            Self::Macos => "macos",
            Self::Android => "android",
        }
    }
}

/// The range of module API versions a module works against.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiRange {
    /// Lowest module API version the module works with, `major` or
    /// `major.minor`.
    pub min: String,
    /// Highest module API version the module works with, if it caps one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<String>,
}

/// A `major.minor` API version, where the minor may be unwritten.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct ApiVersion {
    major: u32,
    minor: u32,
}

impl ApiVersion {
    fn parse(text: &str, context: &str) -> Result<Self> {
        let mut parts = text.split('.');
        let major = parts
            .next()
            .and_then(|p| p.parse::<u32>().ok())
            .ok_or_else(|| {
                Error::InvalidModuleManifest(format!("{context}: '{text}' is not an API version"))
            })?;
        let minor = match parts.next() {
            None => 0,
            Some(part) => part.parse::<u32>().map_err(|_| {
                Error::InvalidModuleManifest(format!("{context}: '{text}' is not an API version"))
            })?,
        };
        if parts.next().is_some() {
            return Err(Error::InvalidModuleManifest(format!(
                "{context}: '{text}' has more than major.minor"
            )));
        }
        Ok(Self { major, minor })
    }
}

impl ApiRange {
    /// Whether this build's module API falls inside the range.
    ///
    /// A `max` is inclusive at the minor it names: `max: "0"` means every `0.x`
    /// is acceptable, which is what an author writing `"0"` means. Reading it
    /// as `0.0` would exclude every build after the first.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidModuleManifest`] if either bound is not an API version,
    /// or `max` is below `min`.
    pub fn admits_this_build(&self) -> Result<bool> {
        // Both bounds are parsed and checked against each other *before*
        // either is compared with this build. An inverted range is malformed
        // whoever reads it, and a build that happens to sit below `min` must
        // still report it as malformed rather than answering "no" and leaving
        // the author's mistake undiscovered until some later version.
        let min = ApiVersion::parse(&self.min, "api.min")?;
        let ceiling = match self.max.as_deref() {
            None => None,
            Some(max_text) => {
                let max = ApiVersion::parse(max_text, "api.max")?;
                if max < min {
                    return Err(Error::InvalidModuleManifest(format!(
                        "api.max ({max_text}) is below api.min ({})",
                        self.min
                    )));
                }
                // "0" caps the major, not the minor.
                Some(if max_text.contains('.') {
                    max
                } else {
                    ApiVersion {
                        major: max.major,
                        minor: u32::MAX,
                    }
                })
            }
        };

        let ours = ApiVersion {
            major: MODULE_API_MAJOR,
            minor: MODULE_API_MINOR,
        };
        Ok(ours >= min && ceiling.is_none_or(|ceiling| ours <= ceiling))
    }

    /// The range as an author would read it back, for error messages.
    #[must_use]
    pub fn describe(&self) -> String {
        match &self.max {
            Some(max) => format!(">={} <={max}", self.min),
            None => format!(">={}", self.min),
        }
    }
}

/// How a module is run, and from where.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleRuntime {
    /// The runtime kind.
    #[serde(rename = "type")]
    pub kind: RuntimeKind,
    /// Entry point relative to the module root. Required for `declarative` and
    /// `wasm`; a `native` module has no file to point at.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry: Option<String>,
}

/// Another module required at runtime.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Dependency {
    /// Identifier of the required module.
    pub id: String,
    /// Semver range, npm syntax.
    pub version: String,
    /// An optional dependency may be absent; the module then runs with less.
    #[serde(default, skip_serializing_if = "is_false")]
    pub optional: bool,
}

impl Dependency {
    /// The parsed range.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidVersionRange`] if the range is not npm syntax.
    pub fn range(&self) -> Result<VersionRange> {
        VersionRange::parse(&self.version)
    }
}

/// Takes a reference because that is the signature `skip_serializing_if`
/// requires; by value it would be marginally cheaper and would not compile
/// there.
#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_false(value: &bool) -> bool {
    !*value
}

/// Who wrote the module.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Author {
    /// Display name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Project or homepage URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// How to get in touch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contact: Option<String>,
}

/// Locale overrides for the user-visible strings in a manifest.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalisedText {
    /// Translated name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Translated description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// A detached signature over a module's identity and contents.
///
/// Detached, so the bytes that were signed never change shape. The envelope
/// does not carry the subject: the verifier reconstructs it from the manifest
/// and the content hash it computed itself, which is what makes a signature
/// non-transferable to another version. See
/// `eon-stream-spec/docs/signing-and-revocation.md`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignatureEnvelope {
    /// Signature algorithm. Only `ed25519` exists.
    pub algorithm: SignatureAlgorithm,
    /// Which key made the signature.
    #[serde(rename = "keyId")]
    pub key_id: String,
    /// Base64 signature bytes.
    pub value: String,
    /// When it was signed, RFC 3339.
    #[serde(default, rename = "signedAt", skip_serializing_if = "Option::is_none")]
    pub signed_at: Option<String>,
}

/// The one signature algorithm the contract defines.
///
/// An enum rather than a string so an unknown algorithm is a parse error. A
/// verifier that skips signatures it does not understand verifies nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignatureAlgorithm {
    /// Ed25519: small, fast, no parameter choices to get wrong.
    #[serde(rename = "ed25519")]
    Ed25519,
}

/// A module manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleManifest {
    /// Version of the manifest schema this document is written against.
    #[serde(rename = "schemaVersion")]
    pub schema_version: u32,
    /// Globally unique, reverse-DNS, immutable for the life of the module: it
    /// is the identity used by dependencies, signatures and revocation.
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// What the module is for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// The module's own semantic version.
    pub version: String,
    /// What class of module this is.
    pub kind: ModuleKind,
    /// Module API versions this module works against.
    pub api: ApiRange,
    /// How it is executed. Absent means declarative with no entry, which is
    /// only meaningful for a native first-party module.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime: Option<ModuleRuntime>,
    /// Capabilities requested. Nothing is granted implicitly.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub permissions: Vec<Permission>,
    /// Per-permission justification shown to the user.
    #[serde(
        default,
        rename = "permissionRationale",
        skip_serializing_if = "std::collections::BTreeMap::is_empty"
    )]
    pub permission_rationale: std::collections::BTreeMap<String, String>,
    /// Other modules required at runtime.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dependencies: Vec<Dependency>,
    /// Which build profiles may load this module.
    #[serde(default = "default_builds")]
    pub builds: Vec<BuildProfile>,
    /// Operating systems supported. Empty means all of them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub platforms: Vec<Platform>,
    /// SPDX identifier for the module's own code or content.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub license: Option<String>,
    /// Who wrote it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub author: Option<Author>,
    /// Path within the module, or a `data:` URI. A remote URL is refused:
    /// fetching one would tell its host that this module is installed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub icon: Option<String>,
    /// Locale overrides, keyed by BCP 47 tag.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub i18n: std::collections::BTreeMap<String, LocalisedText>,
    /// Detached signature. Absent in a source tree; required for anything the
    /// client installs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<SignatureEnvelope>,
}

fn default_builds() -> Vec<BuildProfile> {
    vec![BuildProfile::Stream]
}

/// A note that is worth showing a reviewer but is not a reason to refuse.
///
/// Kept separate from [`Error`] on purpose: conflating "this is wrong" with
/// "this is worth a look" means one of the two stops being read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewNote {
    /// Stable identifier for the finding.
    pub code: &'static str,
    /// What was noticed.
    pub detail: String,
}

impl ModuleManifest {
    /// Parse a manifest document.
    ///
    /// # Errors
    ///
    /// [`Error::MalformedJson`] if the bytes are not the JSON this schema
    /// describes — including when an unrecognised key is present.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        serde_json::from_slice(bytes).map_err(|e| Error::MalformedJson {
            message: e.to_string(),
        })
    }

    /// The parsed module version.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidVersion`] if it is not a semantic version.
    pub fn parsed_version(&self) -> Result<Version> {
        Version::parse(&self.version)
    }

    /// The name in `locale`, falling back to the manifest's own `name`.
    #[must_use]
    pub fn localised_name(&self, locale: &str) -> &str {
        localise(&self.i18n, locale, |t| t.name.as_deref()).unwrap_or(&self.name)
    }

    /// The description in `locale`, falling back to the manifest's own.
    #[must_use]
    pub fn localised_description(&self, locale: &str) -> Option<&str> {
        localise(&self.i18n, locale, |t| t.description.as_deref()).or(self.description.as_deref())
    }

    /// The runtime kind, defaulting to declarative when none is declared.
    #[must_use]
    pub fn runtime_kind(&self) -> RuntimeKind {
        self.runtime
            .as_ref()
            .map_or(RuntimeKind::Declarative, |r| r.kind)
    }

    /// Whether the module declares `profile`.
    #[must_use]
    pub fn allows_build(&self, profile: BuildProfile) -> bool {
        self.builds.contains(&profile)
    }

    /// Whether the module runs on `platform`. No declared platforms means no
    /// constraint.
    #[must_use]
    pub fn supports_platform(&self, platform: Platform) -> bool {
        self.platforms.is_empty() || self.platforms.contains(&platform)
    }

    /// Check everything the schema constrains, plus the rules the schema can
    /// state only as prose.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidModuleManifest`] for a structural problem,
    /// [`Error::InvalidVersion`] or [`Error::InvalidVersionRange`] for a
    /// malformed version, and [`Error::UnsupportedModuleApi`] when the declared
    /// API range excludes this build.
    pub fn validate(&self) -> Result<()> {
        let bad = |detail: String| Err(Error::InvalidModuleManifest(detail));

        if self.schema_version != 0 {
            return bad(format!(
                "schemaVersion is {}, this build reads 0",
                self.schema_version
            ));
        }
        validate_module_id(&self.id)?;
        if self.name.is_empty() || self.name.chars().count() > 64 {
            return bad("name must be between 1 and 64 characters".to_owned());
        }
        if self
            .description
            .as_ref()
            .is_some_and(|d| d.chars().count() > 512)
        {
            return bad("description is longer than 512 characters".to_owned());
        }
        let _version = self.parsed_version()?;

        if !self.api.admits_this_build()? {
            return Err(Error::UnsupportedModuleApi {
                module: self.id.clone(),
                wanted: self.api.describe(),
                ours: format!("{MODULE_API_MAJOR}.{MODULE_API_MINOR}"),
            });
        }

        // An entry is what the host opens. Without one, a declarative module is
        // a manifest describing nothing and a wasm module has no binary.
        if let Some(runtime) = &self.runtime {
            let needs_entry = matches!(runtime.kind, RuntimeKind::Declarative | RuntimeKind::Wasm);
            match (&runtime.entry, needs_entry) {
                (None, true) => {
                    return bad(format!(
                        "a {} module must declare runtime.entry",
                        runtime.kind.as_str()
                    ));
                }
                (Some(entry), _) => validate_entry(entry)?,
                (None, false) => {}
            }
        }

        if self.permissions.len() > 16 {
            return bad("more than 16 permissions requested".to_owned());
        }
        let mut seen = self.permissions.clone();
        seen.sort_unstable();
        seen.dedup();
        if seen.len() != self.permissions.len() {
            return bad("the same permission is requested twice".to_owned());
        }

        // The hard boundary of madde 4, stated twice on purpose: in the schema
        // so it cannot be forgotten by an implementation, and here because this
        // is the implementation. A declarative module has no code, so there is
        // nothing that could call a granted host function — a permission
        // request on one is either a mistake or a disguise.
        if self.runtime_kind() == RuntimeKind::Declarative && !self.permissions.is_empty() {
            return bad(format!(
                "a declarative module carries no code and may request no permissions; \
                 '{}' requests {}",
                self.id,
                self.permissions
                    .iter()
                    .map(|p| p.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        if self.kind == ModuleKind::Theme && self.runtime_kind() != RuntimeKind::Declarative {
            return bad(format!(
                "a theme is declarative by definition; '{}' declares {}",
                self.id,
                self.runtime_kind().as_str()
            ));
        }

        if self.dependencies.len() > 16 {
            return bad("more than 16 dependencies declared".to_owned());
        }
        for dependency in &self.dependencies {
            if dependency.id == self.id {
                return bad(format!("'{}' depends on itself", self.id));
            }
            validate_module_id(&dependency.id)?;
            let _range = dependency.range()?;
        }
        let mut ids: Vec<&str> = self.dependencies.iter().map(|d| d.id.as_str()).collect();
        ids.sort_unstable();
        let count = ids.len();
        ids.dedup();
        if ids.len() != count {
            return bad("the same dependency is declared twice".to_owned());
        }

        if self.builds.is_empty() {
            return bad("builds must name at least one profile".to_owned());
        }
        if self.kind.is_edu_only() && self.builds.contains(&BuildProfile::Stream) {
            return bad(format!(
                "a {} module cannot declare the stream build",
                self.kind.as_str()
            ));
        }

        if let Some(icon) = &self.icon {
            validate_icon(icon)?;
        }
        for tag in self.i18n.keys() {
            if !is_bcp47(tag) {
                return bad(format!("'{tag}' is not a language tag"));
            }
        }
        Ok(())
    }

    /// Findings a reviewer should see, which are not grounds for refusal.
    ///
    /// A permission without a rationale is the canonical example: the schema
    /// calls it a review finding, not an error, because refusing over it would
    /// punish the honest author who forgot a sentence while doing nothing to
    /// the dishonest one who writes "needed for features".
    #[must_use]
    pub fn review(&self) -> Vec<ReviewNote> {
        let mut notes = Vec::new();
        for permission in &self.permissions {
            if !self.permission_rationale.contains_key(permission.as_str()) {
                notes.push(ReviewNote {
                    code: "permission-without-rationale",
                    detail: format!(
                        "{} is requested with no rationale to show the user",
                        permission.as_str()
                    ),
                });
            }
        }
        for key in self.permission_rationale.keys() {
            if !self.permissions.iter().any(|p| p.as_str() == key) {
                notes.push(ReviewNote {
                    code: "rationale-without-permission",
                    detail: format!("a rationale is given for '{key}', which is not requested"),
                });
            }
        }
        if self.license.is_none() {
            notes.push(ReviewNote {
                code: "no-license",
                detail: "no SPDX licence identifier".to_owned(),
            });
        }
        if self.description.is_none() {
            notes.push(ReviewNote {
                code: "no-description",
                detail: "no description to show in a listing".to_owned(),
            });
        }
        notes
    }
}

fn localise<'a>(
    map: &'a std::collections::BTreeMap<String, LocalisedText>,
    locale: &str,
    pick: impl Fn(&'a LocalisedText) -> Option<&'a str>,
) -> Option<&'a str> {
    // Exact tag first, then the bare language: a `tr-TR` user should get `tr`
    // rather than falling all the way back to English.
    if let Some(text) = map.get(locale).and_then(&pick) {
        return Some(text);
    }
    let language = locale.split('-').next().unwrap_or(locale);
    map.get(language).and_then(pick)
}

/// Reverse-DNS, lowercase, two to seven labels.
///
/// Matches the schema's pattern. Written out rather than compiled from the
/// pattern string so this crate needs no regex engine, and asserted against
/// the spec's own examples in the tests.
fn validate_module_id(id: &str) -> Result<()> {
    let bad = || {
        Err(Error::InvalidModuleManifest(format!(
            "'{id}' is not a reverse-DNS module id"
        )))
    };
    if id.is_empty() || id.len() > 128 {
        return bad();
    }
    let labels: Vec<&str> = id.split('.').collect();
    if labels.len() < 2 || labels.len() > 7 {
        return bad();
    }
    for label in labels {
        if label.is_empty()
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        {
            return bad();
        }
    }
    Ok(())
}

/// An entry path stays inside the module.
///
/// The package schema has its own path-traversal example for the same reason:
/// `../../autostart` is the oldest trick there is, and a module root is a
/// directory the client created.
fn validate_entry(entry: &str) -> Result<()> {
    let bad = |why: &str| {
        Err(Error::InvalidModuleManifest(format!(
            "runtime.entry '{entry}' {why}"
        )))
    };
    if entry.is_empty() || entry.len() > 256 {
        return bad("must be between 1 and 256 characters");
    }
    if entry.starts_with('/') || entry.starts_with('\\') || entry.contains(':') {
        return bad("must be relative to the module root");
    }
    if entry.split(['/', '\\']).any(|part| part == "..") {
        return bad("must not leave the module root");
    }
    if entry.contains('\0') {
        return bad("contains a null byte");
    }
    Ok(())
}

fn validate_icon(icon: &str) -> Result<()> {
    if icon.len() > 2048 {
        return Err(Error::InvalidModuleManifest(
            "icon is longer than 2048 characters".to_owned(),
        ));
    }
    let lower = icon.to_ascii_lowercase();
    if lower.starts_with("http://") || lower.starts_with("https://") {
        return Err(Error::InvalidModuleManifest(
            "icon must not be a remote URL: fetching one would tell its host that this \
             module is installed"
                .to_owned(),
        ));
    }
    if lower.starts_with("data:") {
        return Ok(());
    }
    validate_entry(icon).map_err(|_| {
        Error::InvalidModuleManifest(format!(
            "icon '{icon}' must be a path inside the module or a data: URI"
        ))
    })
}

fn is_bcp47(tag: &str) -> bool {
    let mut parts = tag.split('-');
    let Some(language) = parts.next() else {
        return false;
    };
    if !(2..=3).contains(&language.len()) || !language.chars().all(|c| c.is_ascii_lowercase()) {
        return false;
    }
    parts.all(|part| {
        (2..=8).contains(&part.len()) && part.chars().all(|c| c.is_ascii_alphanumeric())
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn theme() -> ModuleManifest {
        ModuleManifest {
            schema_version: 0,
            id: "community.example.theme".to_owned(),
            name: "Midnight".to_owned(),
            description: Some("A dark theme".to_owned()),
            version: "1.0.0".to_owned(),
            kind: ModuleKind::Theme,
            api: ApiRange {
                min: "0".to_owned(),
                max: None,
            },
            runtime: Some(ModuleRuntime {
                kind: RuntimeKind::Declarative,
                entry: Some("theme.json".to_owned()),
            }),
            permissions: Vec::new(),
            permission_rationale: std::collections::BTreeMap::new(),
            dependencies: Vec::new(),
            builds: vec![BuildProfile::Stream],
            platforms: Vec::new(),
            license: Some("CC0-1.0".to_owned()),
            author: None,
            icon: None,
            i18n: std::collections::BTreeMap::new(),
            signature: None,
        }
    }

    #[test]
    fn a_plain_theme_validates() {
        theme().validate().unwrap();
    }

    #[test]
    fn an_unknown_key_is_an_error_not_an_extension_point() {
        let json = br#"{
            "schemaVersion": 0, "id": "community.example.t", "name": "T",
            "version": "1.0.0", "kind": "theme", "api": {"min": "0"},
            "postInstallScript": "rm -rf /"
        }"#;
        assert!(ModuleManifest::parse(json).is_err());
    }

    #[test]
    fn an_unknown_permission_does_not_parse() {
        // "Unknown permission, assumed harmless" is how a permission system
        // stops meaning anything.
        let json = br#"{
            "schemaVersion": 0, "id": "community.example.t", "name": "T",
            "version": "1.0.0", "kind": "ui", "api": {"min": "0"},
            "runtime": {"type": "wasm", "entry": "m.wasm"},
            "permissions": ["fs.write.everywhere"]
        }"#;
        assert!(ModuleManifest::parse(json).is_err());
    }

    #[test]
    fn a_theme_may_not_carry_code_or_request_anything() {
        let mut m = theme();
        m.permissions = vec![Permission::NetFetch];
        assert!(m.validate().is_err());

        let mut m = theme();
        m.runtime = Some(ModuleRuntime {
            kind: RuntimeKind::Wasm,
            entry: Some("theme.wasm".to_owned()),
        });
        assert!(m.validate().is_err());
    }

    #[test]
    fn a_declarative_module_requests_nothing() {
        let mut m = theme();
        m.kind = ModuleKind::Ui;
        m.permissions = vec![Permission::UiSurface];
        let err = m.validate().unwrap_err().to_string();
        assert!(err.contains("carries no code"), "{err}");
    }

    #[test]
    fn module_ids_follow_the_schema_pattern() {
        for good in [
            "org.eon.stream.video",
            "community.example.theme",
            "a.b",
            "org.eon.stream.creator.package",
            "x1.y-2.z3",
        ] {
            assert!(validate_module_id(good).is_ok(), "{good} should be valid");
        }
        for bad in [
            "",
            "nodot",
            "Org.Eon.Stream",
            "org..eon",
            "-org.eon",
            "org.eon-",
            "org.eon.a.b.c.d.e.f.g",
            "org.eon.stream!",
        ] {
            assert!(validate_module_id(bad).is_err(), "{bad} should be refused");
        }
    }

    #[test]
    fn an_entry_never_leaves_the_module_root() {
        for bad in [
            "../../autostart",
            "/etc/passwd",
            "C:\\windows\\system32",
            "a/../../b",
            "",
        ] {
            assert!(validate_entry(bad).is_err(), "{bad} should be refused");
        }
        validate_entry("theme.json").unwrap();
        validate_entry("assets/theme.json").unwrap();
    }

    #[test]
    fn a_remote_icon_is_refused() {
        let mut m = theme();
        m.icon = Some("https://cdn.example.org/icon.png".to_owned());
        let err = m.validate().unwrap_err().to_string();
        assert!(err.contains("remote URL"), "{err}");

        m.icon = Some("data:image/png;base64,AAAA".to_owned());
        m.validate().unwrap();
        m.icon = Some("assets/icon.png".to_owned());
        m.validate().unwrap();
    }

    #[test]
    fn an_api_range_this_build_is_outside_is_refused_by_name() {
        let mut m = theme();
        m.api = ApiRange {
            min: "1".to_owned(),
            max: None,
        };
        match m.validate() {
            Err(Error::UnsupportedModuleApi { wanted, ours, .. }) => {
                assert_eq!(wanted, ">=1");
                assert_eq!(ours, "0.1");
            }
            other => panic!("expected an API refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_bare_major_max_caps_the_major_not_the_minor() {
        // An author writing max: "0" means "every 0.x". Reading it as 0.0
        // would exclude every build after the very first.
        let range = ApiRange {
            min: "0".to_owned(),
            max: Some("0".to_owned()),
        };
        assert!(range.admits_this_build().unwrap());

        let narrow = ApiRange {
            min: "0".to_owned(),
            max: Some("0.0".to_owned()),
        };
        assert!(!narrow.admits_this_build().unwrap());
    }

    #[test]
    fn an_inverted_api_range_is_an_error() {
        let range = ApiRange {
            min: "0.5".to_owned(),
            max: Some("0.1".to_owned()),
        };
        assert!(range.admits_this_build().is_err());
    }

    #[test]
    fn edu_kinds_cannot_claim_the_stream_build() {
        let mut m = theme();
        m.kind = ModuleKind::EduTool;
        m.builds = vec![BuildProfile::Stream, BuildProfile::Edu];
        assert!(m.validate().is_err());
        m.builds = vec![BuildProfile::Edu];
        m.validate().unwrap();
    }

    #[test]
    fn a_module_cannot_depend_on_itself_or_twice_on_one_thing() {
        let mut m = theme();
        m.dependencies = vec![Dependency {
            id: m.id.clone(),
            version: "*".to_owned(),
            optional: false,
        }];
        assert!(m.validate().is_err());

        let mut m = theme();
        m.dependencies = vec![
            Dependency {
                id: "org.eon.stream.video".to_owned(),
                version: "^1.0.0".to_owned(),
                optional: false,
            },
            Dependency {
                id: "org.eon.stream.video".to_owned(),
                version: "^2.0.0".to_owned(),
                optional: false,
            },
        ];
        assert!(m.validate().is_err());
    }

    #[test]
    fn review_notes_are_separate_from_refusals() {
        let mut m = theme();
        m.license = None;
        m.description = None;
        m.validate().unwrap();
        let codes: Vec<&str> = m.review().iter().map(|n| n.code).collect();
        assert!(codes.contains(&"no-license"));
        assert!(codes.contains(&"no-description"));
    }

    #[test]
    fn localisation_falls_back_from_region_to_language() {
        let mut m = theme();
        m.i18n.insert(
            "tr".to_owned(),
            LocalisedText {
                name: Some("Gece Yarisi".to_owned()),
                description: None,
            },
        );
        assert_eq!(m.localised_name("tr-TR"), "Gece Yarisi");
        assert_eq!(m.localised_name("tr"), "Gece Yarisi");
        assert_eq!(m.localised_name("de"), "Midnight");
        // A locale override with no description falls back to the manifest's.
        assert_eq!(m.localised_description("tr"), Some("A dark theme"));
    }

    #[test]
    fn round_trips_through_json() {
        let m = theme();
        let json = serde_json::to_vec(&m).unwrap();
        assert_eq!(ModuleManifest::parse(&json).unwrap(), m);
    }
}
