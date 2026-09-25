// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 EON contributors
//
// Additional permission under GNU GPL version 3 section 7:
// see LICENSE-EXCEPTION.md (EON Module ABI Exception 1.0).

//! Addon manifests.
//!
//! These types track the Stremio addon manifest so existing addons parse
//! unchanged, and put EON's own additions under the reserved `eon` key. Unknown
//! fields are kept rather than rejected: refusing an addon over a field we do
//! not recognise would break the compatibility that is the point of the format.
//!
//! The authoritative schema lives in `eon-stream-spec`
//! (`schemas/addon-manifest.v0.schema.json`).

use serde::{Deserialize, Serialize};

/// The addon-API major version this build implements.
///
/// `0` is explicitly unstable (see the plan's scope note).
pub const ADDON_API_MAJOR: u32 = 0;

/// A resource an addon serves.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Resource {
    /// Bare form: the resource applies to every declared content type.
    Name(String),
    /// Object form: the resource is narrowed to specific types and id prefixes.
    Detailed(DetailedResource),
}

/// The object form of [`Resource`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetailedResource {
    /// Resource name, for example `catalog`.
    pub name: String,
    /// Content types this resource is offered for.
    #[serde(default, deserialize_with = "crate::serde_lax::null_to_default")]
    pub types: Vec<String>,
    /// Id prefixes this resource can answer for.
    #[serde(
        default,
        rename = "idPrefixes",
        deserialize_with = "crate::serde_lax::null_to_default"
    )]
    pub id_prefixes: Vec<String>,
}

impl Resource {
    /// The resource name, whichever form was used.
    #[must_use]
    pub fn name(&self) -> &str {
        match self {
            Self::Name(name) => name,
            Self::Detailed(detailed) => &detailed.name,
        }
    }

    /// Whether this resource is offered for `content_type`.
    ///
    /// The bare form applies to every type the addon declares, so the caller
    /// passes that decision in via `addon_declares_type`.
    #[must_use]
    pub fn serves(&self, content_type: &str, addon_declares_type: bool) -> bool {
        match self {
            Self::Name(_) => addon_declares_type,
            Self::Detailed(detailed) => detailed.types.iter().any(|t| t == content_type),
        }
    }

    /// Whether this resource can answer for `id`, given its id prefixes.
    ///
    /// No declared prefixes means no constraint.
    #[must_use]
    pub fn accepts_id(&self, id: &str) -> bool {
        match self {
            Self::Name(_) => true,
            Self::Detailed(detailed) => {
                detailed.id_prefixes.is_empty()
                    || detailed.id_prefixes.iter().any(|p| id.starts_with(p))
            }
        }
    }
}

/// A browsable catalogue an addon offers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Catalog {
    /// Content type of the catalogue's entries.
    #[serde(rename = "type")]
    pub content_type: String,
    /// Catalogue identifier, unique within the addon.
    pub id: String,
    /// Display name. Addons in the wild omit this, so it is optional.
    #[serde(default)]
    pub name: Option<String>,
    /// Query parameters the catalogue understands.
    #[serde(default, deserialize_with = "crate::serde_lax::null_to_default")]
    pub extra: Vec<ExtraProp>,
}

impl Catalog {
    /// Name for display, falling back to the identifier.
    #[must_use]
    pub fn display_name(&self) -> &str {
        self.name.as_deref().unwrap_or(&self.id)
    }

    /// Whether this catalogue accepts a free-text `search` parameter.
    #[must_use]
    pub fn is_searchable(&self) -> bool {
        self.extra.iter().any(|e| e.name == "search")
    }

    /// Parameters the addon requires before it will answer at all.
    #[must_use]
    pub fn required_extra(&self) -> Vec<&str> {
        self.extra
            .iter()
            .filter(|e| e.is_required)
            .map(|e| e.name.as_str())
            .collect()
    }
}

/// A query parameter a catalogue understands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtraProp {
    /// Parameter name, for example `search`, `genre` or `skip`.
    pub name: String,
    /// Whether the catalogue refuses to answer without it.
    #[serde(default, rename = "isRequired")]
    pub is_required: bool,
    /// Allowed values, when the addon enumerates them.
    #[serde(default, deserialize_with = "crate::serde_lax::null_to_default")]
    pub options: Vec<String>,
    /// How many values may be supplied at once.
    #[serde(default, rename = "optionsLimit")]
    pub options_limit: Option<u32>,
}

/// Hints about how an addon behaves.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BehaviorHints {
    /// The addon serves adult content.
    #[serde(default)]
    pub adult: bool,
    /// The addon returns peer-to-peer sources.
    #[serde(default)]
    pub p2p: bool,
    /// The addon has a configuration page.
    #[serde(default)]
    pub configurable: bool,
    /// The addon does nothing useful until configured.
    #[serde(default, rename = "configurationRequired")]
    pub configuration_required: bool,
}

/// EON's own manifest extensions.
///
/// Entirely optional, and nothing here may be required for basic playback — a
/// Stremio client ignores this key, and losing that would forfeit two-way
/// compatibility (madde 15e).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EonExtensions {
    /// Oldest addon-API version this addon works against.
    #[serde(default, rename = "minApi")]
    pub min_api: Option<String>,
    /// Newest major version the addon has been tested against.
    #[serde(default, rename = "maxApi")]
    pub max_api: Option<String>,
    /// Extra HTTPS sources, used as web seeds so distribution survives the
    /// publisher going offline (madde 15d).
    #[serde(default, deserialize_with = "crate::serde_lax::null_to_default")]
    pub mirrors: Vec<String>,
    /// SPDX identifier for content the addon serves itself.
    #[serde(default)]
    pub license: Option<String>,
    /// Accessibility features the addon's own content provides (madde 35).
    #[serde(default)]
    pub accessibility: Option<Accessibility>,
    /// Curriculum metadata, so material is findable the way a teacher searches
    /// for it (madde 16a).
    #[serde(default)]
    pub education: Option<Education>,
}

/// Accessibility features an addon claims for its own content.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Accessibility {
    /// Subtitles are available.
    #[serde(default)]
    pub subtitles: bool,
    /// Transcripts are available.
    #[serde(default)]
    pub transcripts: bool,
    /// An audio description track is available.
    #[serde(default, rename = "audioDescription")]
    pub audio_description: bool,
}

/// Curriculum metadata.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Education {
    /// Grade levels the material targets.
    #[serde(
        default,
        rename = "gradeLevels",
        deserialize_with = "crate::serde_lax::null_to_default"
    )]
    pub grade_levels: Vec<u8>,
    /// Subjects the material covers.
    #[serde(default, deserialize_with = "crate::serde_lax::null_to_default")]
    pub subjects: Vec<String>,
    /// Curriculum the metadata is aligned to, when it is aligned to one.
    #[serde(default)]
    pub curriculum: Option<String>,
}

/// An addon manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddonManifest {
    /// Reverse-DNS identifier, immutable for the addon's life.
    pub id: String,
    /// Addon version.
    pub version: String,
    /// Display name.
    pub name: String,
    /// What the addon is.
    #[serde(default)]
    pub description: Option<String>,
    /// Resources the addon serves.
    #[serde(default, deserialize_with = "crate::serde_lax::null_to_default")]
    pub resources: Vec<Resource>,
    /// Content types the addon serves.
    #[serde(default, deserialize_with = "crate::serde_lax::null_to_default")]
    pub types: Vec<String>,
    /// Browsable catalogues.
    #[serde(default, deserialize_with = "crate::serde_lax::null_to_default")]
    pub catalogs: Vec<Catalog>,
    /// Id prefixes the addon can answer for.
    #[serde(
        default,
        rename = "idPrefixes",
        deserialize_with = "crate::serde_lax::null_to_default"
    )]
    pub id_prefixes: Vec<String>,
    /// Logo URL.
    #[serde(default)]
    pub logo: Option<String>,
    /// Background image URL.
    #[serde(default)]
    pub background: Option<String>,
    /// Contact address for the addon's author.
    #[serde(default, rename = "contactEmail")]
    pub contact_email: Option<String>,
    /// Behaviour hints.
    #[serde(
        default,
        rename = "behaviorHints",
        deserialize_with = "crate::serde_lax::null_to_default"
    )]
    pub behavior_hints: BehaviorHints,
    /// EON extensions.
    #[serde(default, deserialize_with = "crate::serde_lax::null_to_default")]
    pub eon: EonExtensions,
}

impl AddonManifest {
    /// Check that the manifest describes an addon we can actually use.
    ///
    /// # Errors
    ///
    /// [`crate::Error::InvalidManifest`] when a required field is empty, and
    /// [`crate::Error::UnsupportedApiVersion`] when the addon targets an
    /// addon-API major version this build does not implement.
    pub fn validate(&self) -> crate::Result<()> {
        if self.id.trim().is_empty() {
            return Err(crate::Error::InvalidManifest("id is empty".into()));
        }
        if self.name.trim().is_empty() {
            return Err(crate::Error::InvalidManifest("name is empty".into()));
        }
        if self.version.trim().is_empty() {
            return Err(crate::Error::InvalidManifest("version is empty".into()));
        }
        if self.resources.is_empty() {
            return Err(crate::Error::InvalidManifest(
                "addon declares no resources".into(),
            ));
        }
        if self.types.is_empty() {
            return Err(crate::Error::InvalidManifest(
                "addon declares no content types".into(),
            ));
        }
        self.check_api_version()
    }

    /// Refuse an addon-API major version this build does not implement, and say
    /// why (madde 5). Failing obscurely later is worse.
    fn check_api_version(&self) -> crate::Result<()> {
        let Some(min) = self.eon.min_api.as_deref() else {
            return Ok(());
        };
        let major_text = min.split('.').next().unwrap_or(min);
        let Ok(major) = major_text.parse::<u32>() else {
            return Err(crate::Error::InvalidManifest(format!(
                "eon.minApi is not a version: {min}"
            )));
        };
        if major > ADDON_API_MAJOR {
            return Err(crate::Error::UnsupportedApiVersion {
                wanted: major,
                ours: ADDON_API_MAJOR,
            });
        }
        Ok(())
    }

    /// Whether the addon declares `content_type`.
    #[must_use]
    pub fn declares_type(&self, content_type: &str) -> bool {
        self.types.iter().any(|t| t == content_type)
    }

    /// Find a declared resource that serves `content_type`.
    #[must_use]
    pub fn resource_for(&self, resource: &str, content_type: &str) -> Option<&Resource> {
        let declares = self.declares_type(content_type);
        self.resources
            .iter()
            .find(|r| r.name() == resource && r.serves(content_type, declares))
    }

    /// Whether it is worth asking this addon about `id`.
    ///
    /// An addon that declares id prefixes is only asked about ids carrying one
    /// of them, which avoids a pointless request per addon per lookup.
    #[must_use]
    pub fn might_know_id(&self, resource: &str, content_type: &str, id: &str) -> bool {
        let Some(res) = self.resource_for(resource, content_type) else {
            return false;
        };
        if !res.accepts_id(id) {
            return false;
        }
        self.id_prefixes.is_empty() || self.id_prefixes.iter().any(|p| id.starts_with(p))
    }

    /// Catalogues of a given content type.
    #[must_use]
    pub fn catalogs_of_type(&self, content_type: &str) -> Vec<&Catalog> {
        self.catalogs
            .iter()
            .filter(|c| c.content_type == content_type)
            .collect()
    }
}
