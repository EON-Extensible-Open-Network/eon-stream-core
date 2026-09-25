// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 EON contributors
//
// Additional permission under GNU GPL version 3 section 7:
// see LICENSE-EXCEPTION.md (EON Module ABI Exception 1.0).

//! The installed addon list.
//!
//! Order is meaningful: it is the order the user chose, and it is the order
//! results are merged in. Everything here lives on the device — no account, no
//! sync, nothing leaves (madde 7, 31).
//!
//! The registry deliberately exposes two different views:
//!
//! * [`AddonRegistry::addons`] — full records, including the address. Internal.
//! * [`AddonRegistry::summaries`] — id, name, version, capabilities. This is
//!   what a module or a UI layer may see, because an addon address can carry
//!   credentials (madde 4, `docs/module-abi.md`).

use serde::{Deserialize, Serialize};

use crate::{AddonAddress, AddonManifest, Error, Result};

/// One installed addon.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstalledAddon {
    /// Where the addon lives. Never leaves the device.
    pub address: AddonAddress,
    /// The manifest as fetched at install or last refresh.
    pub manifest: AddonManifest,
    /// Whether the addon takes part in lookups.
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_true() -> bool {
    true
}

impl InstalledAddon {
    /// The identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.manifest.id
    }

    /// A view that is safe to hand to a UI layer or a module.
    #[must_use]
    pub fn summary(&self) -> AddonSummary {
        AddonSummary {
            id: self.manifest.id.clone(),
            name: self.manifest.name.clone(),
            version: self.manifest.version.clone(),
            description: self.manifest.description.clone(),
            types: self.manifest.types.clone(),
            resources: self
                .manifest
                .resources
                .iter()
                .map(|r| r.name().to_owned())
                .collect(),
            catalog_count: self.manifest.catalogs.len(),
            enabled: self.enabled,
            configuration_required: self.manifest.behavior_hints.configuration_required,
        }
    }
}

/// What may be shown about an addon without exposing its address.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddonSummary {
    /// Identifier.
    pub id: String,
    /// Display name.
    pub name: String,
    /// Version.
    pub version: String,
    /// Description, when the addon supplies one.
    pub description: Option<String>,
    /// Content types served.
    pub types: Vec<String>,
    /// Resource names served.
    pub resources: Vec<String>,
    /// How many catalogues the addon offers.
    pub catalog_count: usize,
    /// Whether the addon takes part in lookups.
    pub enabled: bool,
    /// Whether the addon says it does nothing useful until configured.
    pub configuration_required: bool,
}

/// The installed addon list, in user order.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AddonRegistry {
    addons: Vec<InstalledAddon>,
}

impl AddonRegistry {
    /// An empty registry.
    ///
    /// The application ships with no addons, ever (madde 9), so this is the
    /// genuine starting state rather than a placeholder.
    #[must_use]
    pub fn new() -> Self {
        Self { addons: Vec::new() }
    }

    /// Restore from stored JSON.
    ///
    /// # Errors
    ///
    /// [`Error::Storage`] when the stored list cannot be read.
    pub fn from_json(json: &str) -> Result<Self> {
        serde_json::from_str(json).map_err(|e| Error::Storage {
            message: e.to_string(),
        })
    }

    /// Serialise for storage.
    ///
    /// # Errors
    ///
    /// [`Error::Storage`] when serialisation fails.
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self).map_err(|e| Error::Storage {
            message: e.to_string(),
        })
    }

    /// Every installed addon, in user order.
    #[must_use]
    pub fn addons(&self) -> &[InstalledAddon] {
        &self.addons
    }

    /// Addons taking part in lookups, in user order.
    pub fn enabled(&self) -> impl Iterator<Item = &InstalledAddon> {
        self.addons.iter().filter(|a| a.enabled)
    }

    /// How many addons are installed.
    #[must_use]
    pub fn len(&self) -> usize {
        self.addons.len()
    }

    /// Whether nothing is installed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.addons.is_empty()
    }

    /// Summaries for display, in user order.
    #[must_use]
    pub fn summaries(&self) -> Vec<AddonSummary> {
        self.addons.iter().map(InstalledAddon::summary).collect()
    }

    /// Look up an installed addon by identifier.
    #[must_use]
    pub fn get(&self, id: &str) -> Option<&InstalledAddon> {
        self.addons.iter().find(|a| a.id() == id)
    }

    /// Add an addon.
    ///
    /// # Errors
    ///
    /// [`Error::AlreadyInstalled`] when an addon with the same identifier is
    /// present. Identity is the manifest id, not the address: the same addon
    /// reachable through two URLs is still one addon.
    pub fn insert(&mut self, addon: InstalledAddon) -> Result<()> {
        if self.get(addon.id()).is_some() {
            return Err(Error::AlreadyInstalled(addon.id().to_owned()));
        }
        self.addons.push(addon);
        Ok(())
    }

    /// Replace an installed addon's record, keeping its position and enabled
    /// state. Used when refreshing a manifest.
    ///
    /// # Errors
    ///
    /// [`Error::NotInstalled`] when nothing carries that identifier.
    pub fn replace(&mut self, addon: InstalledAddon) -> Result<()> {
        let position = self
            .addons
            .iter()
            .position(|a| a.id() == addon.id())
            .ok_or_else(|| Error::NotInstalled(addon.id().to_owned()))?;
        let enabled = self.addons[position].enabled;
        self.addons[position] = InstalledAddon { enabled, ..addon };
        Ok(())
    }

    /// Remove an addon.
    ///
    /// # Errors
    ///
    /// [`Error::NotInstalled`] when nothing carries that identifier.
    pub fn remove(&mut self, id: &str) -> Result<InstalledAddon> {
        let position = self
            .addons
            .iter()
            .position(|a| a.id() == id)
            .ok_or_else(|| Error::NotInstalled(id.to_owned()))?;
        Ok(self.addons.remove(position))
    }

    /// Enable or disable an addon without removing it.
    ///
    /// # Errors
    ///
    /// [`Error::NotInstalled`] when nothing carries that identifier.
    pub fn set_enabled(&mut self, id: &str, enabled: bool) -> Result<()> {
        let addon = self
            .addons
            .iter_mut()
            .find(|a| a.id() == id)
            .ok_or_else(|| Error::NotInstalled(id.to_owned()))?;
        addon.enabled = enabled;
        Ok(())
    }

    /// Move an addon to a new position, clamped to the list.
    ///
    /// # Errors
    ///
    /// [`Error::NotInstalled`] when nothing carries that identifier.
    pub fn reorder(&mut self, id: &str, to: usize) -> Result<()> {
        let from = self
            .addons
            .iter()
            .position(|a| a.id() == id)
            .ok_or_else(|| Error::NotInstalled(id.to_owned()))?;
        let addon = self.addons.remove(from);
        let to = to.min(self.addons.len());
        self.addons.insert(to, addon);
        Ok(())
    }

    /// Enabled addons worth asking about `resource` for this type and id.
    ///
    /// Addons that do not declare the resource, or whose id prefixes rule the id
    /// out, are skipped — one pointless request per addon per lookup adds up
    /// fast.
    pub fn candidates_for<'a>(
        &'a self,
        resource: &'a str,
        content_type: &'a str,
        id: &'a str,
    ) -> impl Iterator<Item = &'a InstalledAddon> {
        self.enabled()
            .filter(move |a| a.manifest.might_know_id(resource, content_type, id))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::manifest::Resource;

    fn addon(id: &str, host: &str) -> InstalledAddon {
        InstalledAddon {
            address: AddonAddress::parse(host).unwrap(),
            manifest: AddonManifest {
                id: id.to_owned(),
                version: "1.0.0".into(),
                name: format!("Addon {id}"),
                description: None,
                resources: vec![Resource::Name("catalog".into())],
                types: vec!["movie".into()],
                catalogs: Vec::new(),
                id_prefixes: Vec::new(),
                logo: None,
                background: None,
                contact_email: None,
                behavior_hints: crate::manifest::BehaviorHints::default(),
                eon: crate::manifest::EonExtensions::default(),
            },
            enabled: true,
        }
    }

    #[test]
    fn identity_is_the_manifest_id_not_the_address() {
        let mut registry = AddonRegistry::new();
        registry
            .insert(addon("a.b.c", "https://one.example.org"))
            .unwrap();
        let err = registry
            .insert(addon("a.b.c", "https://two.example.org"))
            .unwrap_err();
        assert!(matches!(err, Error::AlreadyInstalled(_)));
        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn reorder_clamps_instead_of_failing() {
        let mut registry = AddonRegistry::new();
        for id in ["one", "two", "three"] {
            registry.insert(addon(id, "https://x.example.org")).unwrap();
        }
        registry.reorder("three", 0).unwrap();
        registry.reorder("one", 99).unwrap();
        let order: Vec<&str> = registry.addons().iter().map(InstalledAddon::id).collect();
        assert_eq!(order, ["three", "two", "one"]);
    }

    #[test]
    fn summaries_never_carry_the_address() {
        let mut registry = AddonRegistry::new();
        registry
            .insert(addon("a.b.c", "https://secret.example.org/c/TOKEN"))
            .unwrap();
        let json = serde_json::to_string(&registry.summaries()).unwrap();
        assert!(
            !json.contains("TOKEN"),
            "summary leaked the address: {json}"
        );
        assert!(!json.contains("secret.example.org"));
    }

    #[test]
    fn survives_a_round_trip_through_storage() {
        let mut registry = AddonRegistry::new();
        registry
            .insert(addon("a.b.c", "https://one.example.org"))
            .unwrap();
        registry.set_enabled("a.b.c", false).unwrap();
        let restored = AddonRegistry::from_json(&registry.to_json().unwrap()).unwrap();
        assert_eq!(restored.len(), 1);
        assert!(!restored.addons()[0].enabled);
        assert_eq!(restored.enabled().count(), 0);
    }

    #[test]
    fn replace_keeps_position_and_enabled_state() {
        let mut registry = AddonRegistry::new();
        registry
            .insert(addon("one", "https://x.example.org"))
            .unwrap();
        registry
            .insert(addon("two", "https://y.example.org"))
            .unwrap();
        registry.set_enabled("one", false).unwrap();

        let mut updated = addon("one", "https://x.example.org");
        updated.manifest.version = "2.0.0".into();
        registry.replace(updated).unwrap();

        assert_eq!(registry.addons()[0].id(), "one");
        assert_eq!(registry.addons()[0].manifest.version, "2.0.0");
        assert!(!registry.addons()[0].enabled, "enabled state was not kept");
    }
}
