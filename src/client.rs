// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 EON contributors
//
// Additional permission under GNU GPL version 3 section 7:
// see LICENSE-EXCEPTION.md (EON Module ABI Exception 1.0).

//! The addon protocol client.
//!
//! The host talks to addons through this, never directly. Three rules are
//! enforced here rather than left to callers:
//!
//! * **A resource the manifest does not declare is never requested.** The error
//!   comes back without a round trip.
//! * **Failures are per addon.** One broken addon does not empty a merged
//!   catalogue; it appears in the failure list beside the results (madde 1).
//! * **Responses are untrusted input.** Size is capped, status is checked, and
//!   malformed JSON is an ordinary error rather than a panic.

use serde::de::DeserializeOwned;

use crate::{
    http::{HttpClient, HttpResponse},
    types::{MetaResponse, MetasResponse, StreamsResponse, SubtitlesResponse},
    AddonAddress, AddonFailure, AddonManifest, AddonRegistry, Error, InstalledAddon, Meta,
    MetaPreview, Result, Stream, Subtitle,
};

/// Results of a query that spanned several addons.
///
/// Both halves matter: a caller that shows only `items` hides the fact that half
/// the user's addons are failing, and a caller that only reports `failures`
/// hides the results that did arrive.
#[derive(Debug)]
pub struct Merged<T> {
    /// What came back, in addon order, tagged with the addon that produced it.
    pub items: Vec<(String, Vec<T>)>,
    /// Which addons failed, and why.
    pub failures: Vec<AddonFailure>,
}

impl<T> Merged<T> {
    /// Every item, flattened, losing the addon attribution.
    #[must_use]
    pub fn flattened(self) -> Vec<T> {
        self.items
            .into_iter()
            .flat_map(|(_, items)| items)
            .collect()
    }

    /// How many items arrived in total.
    #[must_use]
    pub fn total(&self) -> usize {
        self.items.iter().map(|(_, items)| items.len()).sum()
    }

    /// Whether every addon that was asked failed.
    #[must_use]
    pub fn all_failed(&self) -> bool {
        self.items.is_empty() && !self.failures.is_empty()
    }
}

/// Talks the addon protocol over a supplied transport.
#[derive(Debug, Clone)]
pub struct AddonClient<C: HttpClient> {
    http: C,
}

impl<C: HttpClient> AddonClient<C> {
    /// Wrap a transport.
    #[must_use]
    pub fn new(http: C) -> Self {
        Self { http }
    }

    /// Fetch and validate a manifest from an address the user supplied.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidAddress`] when the text is not a usable address, plus any
    /// transport, status, JSON or validation error.
    pub fn fetch_manifest(&self, address: &str) -> Result<(AddonAddress, AddonManifest)> {
        let address = AddonAddress::parse(address)?;
        let manifest: AddonManifest = self.get_json(&address.manifest_url())?;
        manifest.validate()?;
        Ok((address, manifest))
    }

    /// Install an addon into the registry.
    ///
    /// This is the whole of "add a plugin": resolve the address, fetch the
    /// manifest, check it is usable, and record it.
    ///
    /// # Errors
    ///
    /// Anything [`Self::fetch_manifest`] can return, plus
    /// [`Error::AlreadyInstalled`].
    pub fn install(&self, registry: &mut AddonRegistry, address: &str) -> Result<InstalledAddon> {
        let (address, manifest) = self.fetch_manifest(address)?;
        let addon = InstalledAddon {
            address,
            manifest,
            enabled: true,
        };
        registry.insert(addon.clone())?;
        Ok(addon)
    }

    /// Re-fetch an installed addon's manifest, keeping its position and enabled
    /// state.
    ///
    /// # Errors
    ///
    /// [`Error::NotInstalled`], plus anything fetching a manifest can return.
    pub fn refresh(&self, registry: &mut AddonRegistry, id: &str) -> Result<InstalledAddon> {
        let existing = registry
            .get(id)
            .ok_or_else(|| Error::NotInstalled(id.to_owned()))?;
        let address = existing.address.clone();
        let manifest: AddonManifest = self.get_json(&address.manifest_url())?;
        manifest.validate()?;
        let updated = InstalledAddon {
            address,
            manifest,
            enabled: existing.enabled,
        };
        registry.replace(updated.clone())?;
        Ok(updated)
    }

    /// Fetch one catalogue page from one addon.
    ///
    /// `extra` carries the protocol's query parameters — `search`, `genre`,
    /// `skip` and whatever else the catalogue declares.
    ///
    /// # Errors
    ///
    /// [`Error::ResourceNotOffered`] when the manifest does not declare
    /// `catalog` for this type, plus any transport, status or JSON error.
    pub fn catalog(
        &self,
        addon: &InstalledAddon,
        content_type: &str,
        catalog_id: &str,
        extra: &[(&str, &str)],
    ) -> Result<Vec<MetaPreview>> {
        self.require_resource(addon, "catalog", content_type)?;
        let url = addon.address.catalog_url(content_type, catalog_id, extra);
        let response: MetasResponse = self.get_json(&url)?;
        Ok(response.metas)
    }

    /// Fetch full metadata for one item from one addon.
    ///
    /// # Errors
    ///
    /// [`Error::ResourceNotOffered`], plus any transport, status or JSON error.
    pub fn meta(&self, addon: &InstalledAddon, content_type: &str, id: &str) -> Result<Meta> {
        self.require_resource(addon, "meta", content_type)?;
        let url = addon.address.resource_url("meta", content_type, id);
        let response: MetaResponse = self.get_json(&url)?;
        Ok(response.meta)
    }

    /// Fetch playable sources for one item from one addon.
    ///
    /// # Errors
    ///
    /// [`Error::ResourceNotOffered`], plus any transport, status or JSON error.
    pub fn streams(
        &self,
        addon: &InstalledAddon,
        content_type: &str,
        id: &str,
    ) -> Result<Vec<Stream>> {
        self.require_resource(addon, "stream", content_type)?;
        let url = addon.address.resource_url("stream", content_type, id);
        let response: StreamsResponse = self.get_json(&url)?;
        Ok(response.streams)
    }

    /// Fetch subtitle tracks for one item from one addon.
    ///
    /// # Errors
    ///
    /// [`Error::ResourceNotOffered`], plus any transport, status or JSON error.
    pub fn subtitles(
        &self,
        addon: &InstalledAddon,
        content_type: &str,
        id: &str,
    ) -> Result<Vec<Subtitle>> {
        self.require_resource(addon, "subtitles", content_type)?;
        let url = addon.address.resource_url("subtitles", content_type, id);
        let response: SubtitlesResponse = self.get_json(&url)?;
        Ok(response.subtitles)
    }

    /// Ask every enabled addon that offers `stream` for this item.
    ///
    /// This is where per-addon isolation earns its keep: the user sees the
    /// sources that were found and, separately, which addons failed.
    pub fn streams_from_all(
        &self,
        registry: &AddonRegistry,
        content_type: &str,
        id: &str,
    ) -> Merged<Stream> {
        self.merge(registry, "stream", content_type, id, |addon| {
            self.streams(addon, content_type, id)
        })
    }

    /// Ask every enabled addon that offers `subtitles` for this item.
    pub fn subtitles_from_all(
        &self,
        registry: &AddonRegistry,
        content_type: &str,
        id: &str,
    ) -> Merged<Subtitle> {
        self.merge(registry, "subtitles", content_type, id, |addon| {
            self.subtitles(addon, content_type, id)
        })
    }

    /// Run a per-addon operation over every candidate, collecting both halves.
    fn merge<T, F>(
        &self,
        registry: &AddonRegistry,
        resource: &str,
        content_type: &str,
        id: &str,
        mut op: F,
    ) -> Merged<T>
    where
        F: FnMut(&InstalledAddon) -> Result<Vec<T>>,
    {
        let mut items = Vec::new();
        let mut failures = Vec::new();

        for addon in registry.candidates_for(resource, content_type, id) {
            match op(addon) {
                Ok(found) if found.is_empty() => {}
                Ok(found) => items.push((addon.id().to_owned(), found)),
                Err(error) => failures.push(AddonFailure {
                    addon_id: addon.id().to_owned(),
                    addon_name: addon.manifest.name.clone(),
                    error,
                }),
            }
        }

        Merged { items, failures }
    }

    /// Refuse to send a request the manifest says will not be answered.
    fn require_resource(
        &self,
        addon: &InstalledAddon,
        resource: &'static str,
        content_type: &str,
    ) -> Result<()> {
        if addon
            .manifest
            .resource_for(resource, content_type)
            .is_none()
        {
            return Err(Error::ResourceNotOffered {
                addon: addon.id().to_owned(),
                resource,
                content_type: content_type.to_owned(),
            });
        }
        Ok(())
    }

    /// Fetch and deserialise, applying the status and size checks.
    fn get_json<T: DeserializeOwned>(&self, url: &str) -> Result<T> {
        let response = self
            .http
            .get(url)
            .map_err(|e| Error::Transport { message: e.message })?;
        self.check(&response)?;
        serde_json::from_slice(&response.body).map_err(|e| Error::MalformedJson {
            message: e.to_string(),
        })
    }

    /// Status and size checks, applied to every response.
    fn check(&self, response: &HttpResponse) -> Result<()> {
        let limit = self.http.limits().max_body_bytes;
        if response.body.len() > limit {
            return Err(Error::ResponseTooLarge { limit });
        }
        if !(200..300).contains(&response.status) {
            return Err(Error::HttpStatus {
                status: response.status,
            });
        }
        Ok(())
    }
}
