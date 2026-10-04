// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 EON contributors
//
// Additional permission under GNU GPL version 3 section 7:
// see LICENSE-EXCEPTION.md (EON Module ABI Exception 1.0).

//! The module manager.
//!
//! Installs, removes, enables, updates and orders modules — and refuses the
//! ones that should be refused. This is v1 item 5 of the plan's
//! definition-of-done, and the part of this crate where a mistake is a
//! security bug rather than a bad afternoon. Hence `panic` and `unwrap` being
//! denied crate-wide: a panic here takes the whole application down.
//!
//! ## Installation is two steps, on purpose
//!
//! [`ModuleStore::prepare`] runs every check and produces a
//! [`PreparedInstall`]; [`ModuleStore::commit`] takes that value and installs
//! it. Nothing can be installed without a `PreparedInstall`, and a
//! `PreparedInstall` cannot exist without having passed the checks — so
//! "the permissions were shown to the user before installing" is a shape the
//! API has, not a convention a caller is asked to remember (madde 3).
//!
//! ## What is refused, and why that list is short
//!
//! * **Anything unsigned.** No exception for first-party modules: they use the
//!   same manifest and the same permission model (madde 3).
//! * **Anything that is not declarative.** v1 has no sandbox, so there is
//!   nowhere safe to run code (madde 4). The `wasm` runtime is named in the
//!   contract and refused by this build, which is different from being
//!   unimagined — the error says so.
//! * **Anything signed with the wrong key for this build.** An Edu build loads
//!   Edu-signed modules only (madde 22), and that is enforced in
//!   [`crate::signature`] where no setting reaches it.
//! * **Anything revoked**, by version or by signing key.
//! * **Anything older than what is installed.** A version never goes backwards
//!   (madde 39).
//!
//! ## Module management is not addon management
//!
//! [`crate::registry`] holds *addons*: remote HTTP services the user points at.
//! This holds *modules*: things installed on the machine. They are separate
//! because their trust models are nothing alike — an addon runs on someone
//! else's computer and is never trusted, a module runs on this one and is
//! signed.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::{
    error::{Error, Result},
    module::{
        BuildProfile, ModuleKind, ModuleManifest, Permission, Platform, ReviewNote, RuntimeKind,
    },
    revocation::{RevocationAction, RevocationReason, RevocationStatus, RevocationStore},
    semver::Version,
    signature::{Artefact, Subject, TrustStore},
};

/// Why a module is not currently running.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum DisabledReason {
    /// The user turned it off.
    User,
    /// This version is revoked.
    Revoked {
        /// Why it was revoked.
        reason: RevocationReason,
        /// Where to read more.
        advisory: Option<String>,
    },
    /// The key that signed it is revoked, which revokes everything it signed.
    KeyRevoked {
        /// Identifier of the revoked key.
        key_id: String,
        /// Why the key was revoked.
        reason: RevocationReason,
    },
    /// A required dependency is absent, so it cannot run yet. Recoverable:
    /// installing the dependency re-enables it.
    MissingDependency {
        /// Identifier of the missing module.
        dependency: String,
        /// The range that was asked for.
        range: String,
    },
    /// The module does not run on this platform.
    Platform,
}

impl DisabledReason {
    /// Whether installing or enabling something else could lift this.
    ///
    /// A revocation never lifts itself, so [`ModuleStore::reconcile`] must not
    /// re-enable a revoked module when its dependency turns up.
    #[must_use]
    pub const fn is_recoverable(&self) -> bool {
        matches!(self, Self::MissingDependency { .. })
    }

    /// Message key for the reason, for a host that renders its own text.
    ///
    /// [`Self::describe`] is English-only and is a diagnostic; a host showing
    /// this to a person uses this key with [`Self::message_arguments`] and
    /// [`crate::i18n`] (madde 40).
    #[must_use]
    pub const fn message_key(&self) -> &'static str {
        match self {
            Self::User => "cli.module.off.user",
            Self::Revoked { .. } => "cli.module.off.revoked",
            Self::KeyRevoked { .. } => "cli.module.off.keyrevoked",
            Self::MissingDependency { .. } => "cli.module.off.dependency",
            Self::Platform => "cli.module.off.platform",
        }
    }

    /// The substitutions [`Self::message_key`]'s message expects, in order.
    #[must_use]
    pub fn message_arguments(&self) -> Vec<String> {
        match self {
            Self::User | Self::Platform => Vec::new(),
            Self::Revoked { reason, advisory } => vec![
                reason.as_str().to_owned(),
                advisory.clone().unwrap_or_default(),
            ],
            Self::KeyRevoked { key_id, reason } => {
                vec![key_id.clone(), reason.as_str().to_owned()]
            }
            Self::MissingDependency { dependency, range } => {
                vec![dependency.clone(), range.clone()]
            }
        }
    }

    /// A line fit to show a person.
    ///
    /// English, and a diagnostic: for text shown to a person, a host renders
    /// [`Self::message_key`] through its own catalogue.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::User => "turned off".to_owned(),
            Self::Revoked { reason, advisory } => match advisory {
                Some(advisory) => format!("revoked: {} — {advisory}", reason.as_str()),
                None => format!("revoked: {}", reason.as_str()),
            },
            Self::KeyRevoked { key_id, reason } => {
                format!("its signing key '{key_id}' is revoked: {}", reason.as_str())
            }
            Self::MissingDependency { dependency, range } => {
                format!("needs {dependency} {range}, which is not installed")
            }
            Self::Platform => "not built for this platform".to_owned(),
        }
    }
}

/// An installed module.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstalledModule {
    /// Its manifest, as verified at install time.
    pub manifest: ModuleManifest,
    /// Hex SHA-256 of the content that was installed. Kept so the signature
    /// can be re-checked later without re-reading the module.
    #[serde(rename = "contentSha256")]
    pub content_sha256: String,
    /// Which key signed it. Needed to apply a key revocation afterwards: a key
    /// revoked next year has to reach a module installed today.
    #[serde(rename = "signedBy")]
    pub signed_by: String,
    /// When it was installed, Unix seconds.
    #[serde(rename = "installedAt")]
    pub installed_at: i64,
    /// Whether it is running.
    pub enabled: bool,
    /// Why not, when it is not.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disabled_reason: Option<DisabledReason>,
}

impl InstalledModule {
    /// Its identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.manifest.id
    }

    /// Its version.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidVersion`] if the stored manifest carries a malformed
    /// version, which means the store was edited by hand.
    pub fn version(&self) -> Result<Version> {
        self.manifest.parsed_version()
    }

    /// The subject its signature binds to.
    #[must_use]
    pub fn subject(&self) -> Subject {
        Subject {
            id: self.manifest.id.clone(),
            version: self.manifest.version.clone(),
            sha256: self.content_sha256.clone(),
        }
    }
}

/// A module that has passed every check and is ready to install.
///
/// Carries the permissions it will be granted so the host can show them, and
/// cannot be constructed except by [`ModuleStore::prepare`].
#[derive(Debug, Clone)]
pub struct PreparedInstall {
    module: InstalledModule,
    replaces: Option<Version>,
    missing_required: Vec<(String, String)>,
    notes: Vec<ReviewNote>,
}

impl PreparedInstall {
    /// The manifest that will be installed.
    #[must_use]
    pub fn manifest(&self) -> &ModuleManifest {
        &self.module.manifest
    }

    /// Permissions the user is being asked to grant, with the author's
    /// rationale where one was given.
    ///
    /// In v1 this is always empty, because only declarative modules install
    /// and a declarative module may request nothing. It is here rather than
    /// deferred because the prompt is the part that must exist *before* the
    /// sandbox does: a permission model retrofitted after the first
    /// code-executing module ships is a permission model nobody believes.
    #[must_use]
    pub fn permissions(&self) -> Vec<(Permission, Option<&str>)> {
        self.module
            .manifest
            .permissions
            .iter()
            .map(|p| {
                (
                    *p,
                    self.module
                        .manifest
                        .permission_rationale
                        .get(p.as_str())
                        .map(String::as_str),
                )
            })
            .collect()
    }

    /// The version this will replace, when it is an update.
    #[must_use]
    pub fn replaces(&self) -> Option<&Version> {
        self.replaces.as_ref()
    }

    /// Required dependencies that are not installed, as `(id, range)`.
    ///
    /// Not a refusal: the module installs and stays disabled until they are
    /// there, and the host offers to fetch them (madde 16c). Refusing outright
    /// would make a two-module install an ordering puzzle for the user.
    #[must_use]
    pub fn missing_required(&self) -> &[(String, String)] {
        &self.missing_required
    }

    /// Findings worth showing a reviewer.
    #[must_use]
    pub fn notes(&self) -> &[ReviewNote] {
        &self.notes
    }

    /// Which key signed it.
    #[must_use]
    pub fn signed_by(&self) -> &str {
        &self.module.signed_by
    }
}

/// The installed modules, in load order.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleStore {
    /// Schema version of the stored document.
    #[serde(rename = "schemaVersion")]
    schema_version: u32,
    /// Which build this store belongs to. Stored rather than passed in, so a
    /// store written by an Edu build cannot be silently read by a Stream one.
    build: BuildProfile,
    modules: Vec<InstalledModule>,
}

impl ModuleStore {
    /// An empty store for `build`.
    #[must_use]
    pub fn new(build: BuildProfile) -> Self {
        Self {
            schema_version: 0,
            build,
            modules: Vec::new(),
        }
    }

    /// Which build this store is for.
    #[must_use]
    pub const fn build(&self) -> BuildProfile {
        self.build
    }

    /// Every installed module.
    #[must_use]
    pub fn all(&self) -> &[InstalledModule] {
        &self.modules
    }

    /// The modules that are actually running.
    #[must_use]
    pub fn enabled(&self) -> Vec<&InstalledModule> {
        self.modules.iter().filter(|m| m.enabled).collect()
    }

    /// Enabled modules of one kind, in load order.
    #[must_use]
    pub fn enabled_of_kind(&self, kind: ModuleKind) -> Vec<&InstalledModule> {
        self.modules
            .iter()
            .filter(|m| m.enabled && m.manifest.kind == kind)
            .collect()
    }

    /// One module by identifier.
    #[must_use]
    pub fn get(&self, id: &str) -> Option<&InstalledModule> {
        self.modules.iter().find(|m| m.id() == id)
    }

    /// How many are installed.
    #[must_use]
    pub fn len(&self) -> usize {
        self.modules.len()
    }

    /// Whether nothing is installed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.modules.is_empty()
    }

    /// Run every check against a candidate and produce something installable.
    ///
    /// `content` is the module's bytes — whatever the signature was made over,
    /// which for a declarative module is the entry document. The hash is
    /// computed here and never taken from the caller: a caller-supplied hash
    /// makes the whole chain decorative.
    ///
    /// # Errors
    ///
    /// The first check that fails, in an order chosen so the message is the
    /// most useful one available: manifest validity, then build profile, then
    /// runtime support, then signature, then revocation, then version
    /// ordering. A module refused for being unsigned should not first be
    /// refused for a platform mismatch that would not have mattered.
    pub fn prepare(
        &self,
        manifest: ModuleManifest,
        content: &[u8],
        trust: &TrustStore,
        revocations: &RevocationStore,
        now: i64,
    ) -> Result<PreparedInstall> {
        manifest.validate()?;
        let version = manifest.parsed_version()?;

        if !manifest.allows_build(self.build) {
            return Err(Error::ModuleNotAllowedInBuild {
                module: manifest.id.clone(),
                build: self.build.as_str(),
            });
        }

        // v1 executes no third-party code, because there is no sandbox to
        // execute it in (madde 4). `native` is not refused for being dangerous
        // but for being impossible: a native module is compiled into the
        // client, so there is nothing here to install.
        match manifest.runtime_kind() {
            RuntimeKind::Declarative => {}
            kind @ (RuntimeKind::Wasm | RuntimeKind::Native) => {
                return Err(Error::ModuleRuntimeNotSupported {
                    module: manifest.id.clone(),
                    runtime: kind.as_str(),
                });
            }
        }

        // Nothing the client installs is unsigned, first-party included.
        let envelope = manifest
            .signature
            .clone()
            .ok_or_else(|| Error::SignatureMissing(manifest.id.clone()))?;
        let subject = Subject::of(&manifest.id, &manifest.version, content);
        let key = trust.verify(&envelope, &subject, Artefact::Module, self.build, now)?;
        let signed_by = key.key_id.clone();

        // Revocation after signature verification: a revoked module that is
        // also unsigned should be reported as unsigned, since that is the more
        // fundamental problem.
        if let RevocationStatus::Revoked {
            reason, advisory, ..
        } = revocations.status(&manifest.id, &version)?
        {
            return Err(Error::ModuleRevoked {
                id: manifest.id.clone(),
                version: manifest.version.clone(),
                reason: reason.as_str().to_owned(),
                advisory,
            });
        }
        if let Some(list) = revocations.held() {
            if let Some(revoked) = list.revoked_keys.iter().find(|k| k.key_id == signed_by) {
                return Err(Error::SigningKeyRevoked {
                    key_id: signed_by,
                    reason: revoked.reason.as_str().to_owned(),
                });
            }
        }

        // A version never goes backwards (madde 39). Equal is refused too:
        // re-installing the same version over itself is either a mistake or an
        // attempt to replace content under an unchanged version number, and
        // the content hash would differ while the version did not.
        let replaces = match self.get(&manifest.id) {
            None => None,
            Some(existing) => {
                let installed = existing.version()?;
                if version <= installed {
                    return Err(Error::ModuleDowngrade {
                        module: manifest.id.clone(),
                        installed: installed.to_string(),
                        offered: version.to_string(),
                    });
                }
                Some(installed)
            }
        };

        let missing_required = self.missing_required_for(&manifest)?;
        let notes = manifest.review();

        Ok(PreparedInstall {
            module: InstalledModule {
                manifest,
                content_sha256: subject.sha256,
                signed_by,
                installed_at: now,
                enabled: true,
                disabled_reason: None,
            },
            replaces,
            missing_required,
            notes,
        })
    }

    /// Install something [`prepare`](Self::prepare) approved.
    ///
    /// Returns the module as it ended up — which may be disabled, if a
    /// required dependency or this platform is missing.
    ///
    /// # Errors
    ///
    /// [`Error::DependencyCycle`] if installing this would make the load order
    /// impossible. Checked here rather than in `prepare` because a cycle is a
    /// property of the whole set, not of the candidate.
    pub fn commit(&mut self, prepared: PreparedInstall) -> Result<&InstalledModule> {
        let id = prepared.module.manifest.id.clone();
        let mut module = prepared.module;

        if let Some(platform) = Platform::host() {
            if !module.manifest.supports_platform(platform) {
                module.enabled = false;
                module.disabled_reason = Some(DisabledReason::Platform);
            }
        }
        if module.enabled {
            if let Some((dependency, range)) = prepared.missing_required.first() {
                module.enabled = false;
                module.disabled_reason = Some(DisabledReason::MissingDependency {
                    dependency: dependency.clone(),
                    range: range.clone(),
                });
            }
        }

        match self.modules.iter().position(|m| m.id() == id) {
            // An update keeps the module's place in the load order: a user who
            // ordered their modules did not ask for that to be undone by an
            // update.
            Some(index) => self.modules[index] = module,
            None => self.modules.push(module),
        }

        // Verify the order is still computable, and undo the install if it is
        // not, so a cycle cannot leave the store unusable.
        if let Err(e) = self.load_order() {
            self.modules.retain(|m| m.id() != id);
            return Err(e);
        }

        self.reconcile();
        self.get(&id)
            .ok_or_else(|| Error::ModuleNotInstalled(id.clone()))
    }

    /// Remove a module.
    ///
    /// # Errors
    ///
    /// [`Error::ModuleNotInstalled`] if nothing carries that id, or
    /// [`Error::MissingDependency`] if something installed requires it — said
    /// plainly rather than quietly breaking the dependent.
    pub fn remove(&mut self, id: &str) -> Result<InstalledModule> {
        let index = self
            .modules
            .iter()
            .position(|m| m.id() == id)
            .ok_or_else(|| Error::ModuleNotInstalled(id.to_owned()))?;

        if let Some(dependent) = self.modules.iter().find(|m| {
            m.id() != id
                && m.manifest
                    .dependencies
                    .iter()
                    .any(|d| d.id == id && !d.optional)
        }) {
            return Err(Error::MissingDependency {
                module: dependent.id().to_owned(),
                dependency: id.to_owned(),
                range: "installed".to_owned(),
            });
        }

        let removed = self.modules.remove(index);
        self.reconcile();
        Ok(removed)
    }

    /// Turn a module on.
    ///
    /// # Errors
    ///
    /// [`Error::ModuleNotInstalled`] if nothing carries that id, or the reason
    /// it cannot be enabled — a revoked module does not come back because a
    /// user asked.
    pub fn enable(&mut self, id: &str) -> Result<()> {
        let (reason, manifest) = {
            let module = self
                .get(id)
                .ok_or_else(|| Error::ModuleNotInstalled(id.to_owned()))?;
            (module.disabled_reason.clone(), module.manifest.clone())
        };

        match reason {
            Some(DisabledReason::Revoked { reason, advisory }) => {
                return Err(Error::ModuleRevoked {
                    id: id.to_owned(),
                    version: manifest.version,
                    reason: reason.as_str().to_owned(),
                    advisory,
                })
            }
            Some(DisabledReason::KeyRevoked { key_id, reason }) => {
                return Err(Error::SigningKeyRevoked {
                    key_id,
                    reason: reason.as_str().to_owned(),
                })
            }
            Some(DisabledReason::MissingDependency { dependency, range }) => {
                return Err(Error::MissingDependency {
                    module: id.to_owned(),
                    dependency,
                    range,
                })
            }
            Some(DisabledReason::Platform) => {
                return Err(Error::ModuleNotAllowedInBuild {
                    module: id.to_owned(),
                    build: "this platform",
                })
            }
            Some(DisabledReason::User) | None => {}
        }

        if let Some(module) = self.modules.iter_mut().find(|m| m.id() == id) {
            module.enabled = true;
            module.disabled_reason = None;
        }
        self.reconcile();
        Ok(())
    }

    /// Turn a module off at the user's request.
    ///
    /// # Errors
    ///
    /// [`Error::ModuleNotInstalled`] if nothing carries that id.
    pub fn disable(&mut self, id: &str) -> Result<()> {
        let module = self
            .modules
            .iter_mut()
            .find(|m| m.id() == id)
            .ok_or_else(|| Error::ModuleNotInstalled(id.to_owned()))?;
        module.enabled = false;
        module.disabled_reason = Some(DisabledReason::User);
        self.reconcile();
        Ok(())
    }

    /// Move a module to a new position in the load order.
    ///
    /// # Errors
    ///
    /// [`Error::ModuleNotInstalled`] if nothing carries that id.
    pub fn reorder(&mut self, id: &str, to: usize) -> Result<()> {
        let from = self
            .modules
            .iter()
            .position(|m| m.id() == id)
            .ok_or_else(|| Error::ModuleNotInstalled(id.to_owned()))?;
        let to = to.min(self.modules.len().saturating_sub(1));
        let module = self.modules.remove(from);
        self.modules.insert(to, module);
        Ok(())
    }

    /// Apply a revocation list to what is installed.
    ///
    /// Disables every revoked version and every module signed by a revoked
    /// key, and returns what it did. A revoked module is **disabled and
    /// reported**, never silently removed: quiet removal teaches users to
    /// distrust the updater.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidVersionRange`] if the held list has an unusable entry,
    /// or [`Error::InvalidVersion`] if a stored manifest does.
    pub fn apply_revocations(
        &mut self,
        revocations: &RevocationStore,
        now: i64,
    ) -> Result<Vec<RevocationAction>> {
        let _ = now;
        let mut actions = Vec::new();
        let revoked_keys: BTreeMap<String, RevocationReason> = revocations
            .held()
            .map(|list| {
                list.revoked_keys
                    .iter()
                    .map(|k| (k.key_id.clone(), k.reason))
                    .collect()
            })
            .unwrap_or_default();

        // Decide first, mutate second: `status` borrows the store immutably.
        let mut verdicts = Vec::new();
        for module in &self.modules {
            let version = module.version()?;
            if let RevocationStatus::Revoked {
                reason, advisory, ..
            } = revocations.status(module.id(), &version)?
            {
                verdicts.push((
                    module.id().to_owned(),
                    module.manifest.version.clone(),
                    module.enabled,
                    DisabledReason::Revoked { reason, advisory },
                    reason,
                    None,
                ));
            } else if let Some(reason) = revoked_keys.get(&module.signed_by) {
                verdicts.push((
                    module.id().to_owned(),
                    module.manifest.version.clone(),
                    module.enabled,
                    DisabledReason::KeyRevoked {
                        key_id: module.signed_by.clone(),
                        reason: *reason,
                    },
                    *reason,
                    Some(module.signed_by.clone()),
                ));
            }
        }

        for (id, version, was_enabled, disabled_reason, reason, _key) in verdicts {
            let advisory = match &disabled_reason {
                DisabledReason::Revoked { advisory, .. } => advisory.clone(),
                _ => None,
            };
            if let Some(module) = self.modules.iter_mut().find(|m| m.id() == id) {
                module.enabled = false;
                module.disabled_reason = Some(disabled_reason);
            }
            actions.push(RevocationAction {
                module_id: id,
                version,
                reason,
                advisory,
                was_enabled,
            });
        }
        Ok(actions)
    }

    /// Recompute the disables that depend on what else is installed.
    ///
    /// Enables a module whose missing dependency has turned up, and disables
    /// one whose dependency went away. Never touches a module disabled for a
    /// reason that installing something else cannot lift — a revoked module
    /// does not come back because its dependency did.
    pub fn reconcile(&mut self) {
        // Iterate to a fixed point: enabling A can satisfy B, which can
        // satisfy C. Bounded by the module count, so a cycle cannot spin here
        // even though `load_order` would have refused one.
        for _ in 0..=self.modules.len() {
            let mut changed = false;
            let snapshot: Vec<(String, bool)> = self
                .modules
                .iter()
                .map(|m| (m.id().to_owned(), m.enabled))
                .collect();

            let mut updates: Vec<(String, Option<DisabledReason>)> = Vec::new();
            for module in &self.modules {
                let unmet = module
                    .manifest
                    .dependencies
                    .iter()
                    .filter(|d| !d.optional)
                    .find_map(|d| {
                        let satisfied = snapshot.iter().any(|(id, enabled)| {
                            *enabled
                                && id == &d.id
                                && self.get(id).is_some_and(|installed| {
                                    match (d.range(), installed.version()) {
                                        (Ok(range), Ok(version)) => range.matches(&version),
                                        _ => false,
                                    }
                                })
                        });
                        if satisfied {
                            None
                        } else {
                            Some((d.id.clone(), d.version.clone()))
                        }
                    });

                match (&module.disabled_reason, unmet) {
                    // A dependency arrived.
                    (Some(reason), None) if reason.is_recoverable() => {
                        updates.push((module.id().to_owned(), None));
                    }
                    // A dependency is gone, and nothing more serious is wrong.
                    (None, Some((dependency, range))) => {
                        updates.push((
                            module.id().to_owned(),
                            Some(DisabledReason::MissingDependency { dependency, range }),
                        ));
                    }
                    _ => {}
                }
            }

            for (id, reason) in updates {
                if let Some(module) = self.modules.iter_mut().find(|m| m.id() == id) {
                    module.enabled = reason.is_none();
                    module.disabled_reason = reason;
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }
    }

    /// Identifiers in dependency order: a module comes after everything it
    /// depends on.
    ///
    /// # Errors
    ///
    /// [`Error::DependencyCycle`] naming the modules involved. A cycle is
    /// reported rather than broken arbitrarily: whichever edge got dropped
    /// would be a decision nobody made.
    pub fn load_order(&self) -> Result<Vec<String>> {
        let mut ordered: Vec<String> = Vec::with_capacity(self.modules.len());
        let mut done: BTreeSet<String> = BTreeSet::new();
        let mut remaining: Vec<&InstalledModule> = self.modules.iter().collect();

        while !remaining.is_empty() {
            let before = remaining.len();
            remaining.retain(|module| {
                let ready = module.manifest.dependencies.iter().all(|d| {
                    // A dependency that is not installed at all cannot create
                    // a cycle, so it does not block the ordering; it is
                    // handled as a disable instead.
                    done.contains(&d.id) || self.get(&d.id).is_none()
                });
                if ready {
                    ordered.push(module.id().to_owned());
                    done.insert(module.id().to_owned());
                }
                !ready
            });
            if remaining.len() == before {
                let involved: Vec<&str> = remaining.iter().map(|m| m.id()).collect();
                return Err(Error::DependencyCycle(involved.join(" -> ")));
            }
        }
        Ok(ordered)
    }

    /// Required dependencies of `manifest` that are not installed and enabled.
    fn missing_required_for(&self, manifest: &ModuleManifest) -> Result<Vec<(String, String)>> {
        let mut missing = Vec::new();
        for dependency in manifest.dependencies.iter().filter(|d| !d.optional) {
            let range = dependency.range()?;
            let satisfied = self
                .get(&dependency.id)
                .map(|installed| installed.version().map(|v| range.matches(&v)))
                .transpose()?
                .unwrap_or(false);
            if !satisfied {
                missing.push((dependency.id.clone(), dependency.version.clone()));
            }
        }
        Ok(missing)
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
    /// [`Error::Storage`] if the bytes are not a store this build reads, or
    /// [`Error::ModuleNotAllowedInBuild`] if the store was written by a
    /// different build profile. The second is the one that matters: an Edu
    /// store read by a Stream build would carry Edu-signed modules into a
    /// build that must not have them (madde 22).
    pub fn from_json(text: &str, build: BuildProfile) -> Result<Self> {
        let store: Self = serde_json::from_str(text).map_err(|e| Error::Storage {
            message: e.to_string(),
        })?;
        if store.schema_version != 0 {
            return Err(Error::Storage {
                message: format!(
                    "module store schemaVersion is {}, this build reads 0",
                    store.schema_version
                ),
            });
        }
        if store.build != build {
            return Err(Error::ModuleNotAllowedInBuild {
                module: format!("the stored module list ({} modules)", store.modules.len()),
                build: build.as_str(),
            });
        }
        Ok(store)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::{
        module::{ApiRange, Dependency, ModuleRuntime, SignatureAlgorithm, SignatureEnvelope},
        revocation::{RevocationList, RevokedKey, RevokedModule},
        signature::{KeyPurpose, TrustedKey},
    };
    use base64::Engine as _;

    const TEST_SECRET: [u8; 32] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ];
    const NOW: i64 = 1_780_000_000;
    const CONTENT: &[u8] = b"{\"schemaVersion\":0,\"colors\":{}}";

    fn signing_key() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&TEST_SECRET)
    }

    fn public_b64() -> String {
        base64::engine::general_purpose::STANDARD.encode(signing_key().verifying_key().to_bytes())
    }

    fn trust(purpose: KeyPurpose) -> TrustStore {
        TrustStore::from_keys(vec![TrustedKey {
            key_id: format!("{}-2026-a", purpose.as_str()),
            purpose,
            public_key: public_b64(),
            not_before: "2026-01-01T00:00:00Z".to_owned(),
            not_after: "2027-01-01T00:00:00Z".to_owned(),
            comment: None,
        }])
    }

    fn manifest(id: &str, version: &str) -> ModuleManifest {
        ModuleManifest {
            schema_version: 0,
            id: id.to_owned(),
            name: "Test module".to_owned(),
            description: Some("For tests".to_owned()),
            version: version.to_owned(),
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
            permission_rationale: BTreeMap::new(),
            dependencies: Vec::new(),
            builds: vec![BuildProfile::Stream],
            platforms: Vec::new(),
            license: Some("CC0-1.0".to_owned()),
            author: None,
            icon: None,
            i18n: BTreeMap::new(),
            signature: None,
        }
    }

    fn sign(mut manifest: ModuleManifest, content: &[u8], key_id: &str) -> ModuleManifest {
        use ed25519_dalek::Signer as _;
        let subject = Subject::of(&manifest.id, &manifest.version, content);
        let signature = signing_key().sign(&subject.canonical_bytes());
        manifest.signature = Some(SignatureEnvelope {
            algorithm: SignatureAlgorithm::Ed25519,
            key_id: key_id.to_owned(),
            value: base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()),
            signed_at: None,
        });
        manifest
    }

    fn signed(id: &str, version: &str) -> ModuleManifest {
        sign(manifest(id, version), CONTENT, "module-2026-a")
    }

    fn store() -> ModuleStore {
        ModuleStore::new(BuildProfile::Stream)
    }

    fn install(store: &mut ModuleStore, manifest: ModuleManifest) -> Result<()> {
        let prepared = store.prepare(
            manifest,
            CONTENT,
            &trust(KeyPurpose::Module),
            &RevocationStore::new(),
            NOW,
        )?;
        store.commit(prepared)?;
        Ok(())
    }

    #[test]
    fn a_signed_declarative_module_installs() {
        let mut store = store();
        install(&mut store, signed("community.example.theme", "1.0.0")).unwrap();
        assert_eq!(store.len(), 1);
        let module = store.get("community.example.theme").unwrap();
        assert!(module.enabled);
        assert_eq!(module.signed_by, "module-2026-a");
        assert_eq!(
            module.content_sha256,
            crate::signature::content_hash(CONTENT)
        );
    }

    #[test]
    fn nothing_unsigned_installs_not_even_first_party() {
        let mut store = store();
        let err = install(&mut store, manifest("org.eon.stream.video", "1.0.0")).unwrap_err();
        assert!(matches!(err, Error::SignatureMissing(_)), "{err}");
        assert!(store.is_empty());
    }

    #[test]
    fn content_that_does_not_match_the_signature_is_refused() {
        // The hash is computed here and never taken from the caller, so
        // swapping the content after signing has to fail.
        let store = store();
        let prepared = store.prepare(
            signed("community.example.theme", "1.0.0"),
            b"different content",
            &trust(KeyPurpose::Module),
            &RevocationStore::new(),
            NOW,
        );
        assert!(matches!(prepared, Err(Error::SignatureInvalid(_))));
    }

    #[test]
    fn a_wasm_module_is_refused_by_name_rather_than_ignored() {
        // v1 has no sandbox (madde 4). The contract names the runtime, so the
        // refusal says "this build does not execute it" -- not "unknown".
        let mut m = manifest("community.example.tool", "1.0.0");
        m.kind = ModuleKind::Ui;
        m.runtime = Some(ModuleRuntime {
            kind: RuntimeKind::Wasm,
            entry: Some("tool.wasm".to_owned()),
        });
        let m = sign(m, CONTENT, "module-2026-a");
        let mut store = store();
        match install(&mut store, m) {
            Err(Error::ModuleRuntimeNotSupported { runtime, .. }) => assert_eq!(runtime, "wasm"),
            other => panic!("expected a runtime refusal, got {other:?}"),
        }
    }

    #[test]
    fn an_edu_module_does_not_install_into_a_stream_build() {
        let mut m = manifest("org.eon.edu.attendance", "1.0.0");
        m.kind = ModuleKind::EduTool;
        m.builds = vec![BuildProfile::Edu];
        let m = sign(m, CONTENT, "module-2026-a");
        let mut store = store();
        assert!(matches!(
            install(&mut store, m),
            Err(Error::ModuleNotAllowedInBuild { .. })
        ));
    }

    #[test]
    fn an_edu_build_refuses_a_module_key_signature() {
        // madde 22 at the signature layer: the Edu build does not merely hide
        // the open marketplace, it cannot verify anything from it.
        let mut m = manifest("org.eon.edu.attendance", "1.0.0");
        m.kind = ModuleKind::EduTool;
        m.builds = vec![BuildProfile::Edu];
        let m = sign(m, CONTENT, "module-2026-a");

        let edu = ModuleStore::new(BuildProfile::Edu);
        let prepared = edu.prepare(
            m,
            CONTENT,
            &trust(KeyPurpose::Module),
            &RevocationStore::new(),
            NOW,
        );
        assert!(matches!(prepared, Err(Error::KeyNotUsable { .. })));
    }

    #[test]
    fn a_version_never_goes_backwards() {
        let mut store = store();
        install(&mut store, signed("community.example.theme", "1.2.0")).unwrap();

        for older in ["1.1.0", "1.2.0", "0.9.0"] {
            match install(&mut store, signed("community.example.theme", older)) {
                Err(Error::ModuleDowngrade {
                    installed, offered, ..
                }) => {
                    assert_eq!(installed, "1.2.0");
                    assert_eq!(offered, older);
                }
                other => panic!("{older} should be refused, got {other:?}"),
            }
        }
        install(&mut store, signed("community.example.theme", "1.3.0")).unwrap();
        assert_eq!(
            store
                .get("community.example.theme")
                .unwrap()
                .manifest
                .version,
            "1.3.0"
        );
    }

    #[test]
    fn an_update_keeps_its_place_in_the_load_order() {
        let mut store = store();
        install(&mut store, signed("community.example.a", "1.0.0")).unwrap();
        install(&mut store, signed("community.example.b", "1.0.0")).unwrap();
        install(&mut store, signed("community.example.c", "1.0.0")).unwrap();
        store.reorder("community.example.c", 0).unwrap();

        install(&mut store, signed("community.example.c", "2.0.0")).unwrap();
        let ids: Vec<&str> = store.all().iter().map(InstalledModule::id).collect();
        assert_eq!(
            ids,
            vec![
                "community.example.c",
                "community.example.a",
                "community.example.b"
            ]
        );
    }

    #[test]
    fn a_revoked_version_does_not_install() {
        let revocations = revocation_store(vec![RevokedModule {
            id: "community.example.theme".to_owned(),
            versions: "1.0.0".to_owned(),
            reason: RevocationReason::MaliciousCode,
            revoked_at: crate::revocation::timestamp(NOW - 3600),
            advisory: Some("https://example.org/a".to_owned()),
        }]);
        let store_ = store();
        match store_.prepare(
            signed("community.example.theme", "1.0.0"),
            CONTENT,
            &trust(KeyPurpose::Module),
            &revocations,
            NOW,
        ) {
            Err(Error::ModuleRevoked { reason, .. }) => assert_eq!(reason, "malicious-code"),
            other => panic!("expected a revocation refusal, got {other:?}"),
        }
        // The next version is fine: revocation is version-scoped.
        assert!(store_
            .prepare(
                signed("community.example.theme", "1.0.1"),
                CONTENT,
                &trust(KeyPurpose::Module),
                &revocations,
                NOW,
            )
            .is_ok());
    }

    fn revocation_store(revoked: Vec<RevokedModule>) -> RevocationStore {
        revocation_store_with(revoked, Vec::new())
    }

    fn revocation_store_with(
        revoked: Vec<RevokedModule>,
        revoked_keys: Vec<RevokedKey>,
    ) -> RevocationStore {
        use ed25519_dalek::Signer as _;
        let mut list = RevocationList {
            schema_version: 0,
            issued_at: crate::revocation::timestamp(NOW - 1800),
            next_update: crate::revocation::timestamp(NOW + 7 * 86_400),
            revoked,
            revoked_keys,
            signature: None,
        };
        let subject = list.signing_subject().unwrap();
        let signature = signing_key().sign(&subject.canonical_bytes());
        list.signature = Some(SignatureEnvelope {
            algorithm: SignatureAlgorithm::Ed25519,
            key_id: "release-2026-a".to_owned(),
            value: base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()),
            signed_at: None,
        });
        let mut store = RevocationStore::new();
        store
            .accept(list, &trust(KeyPurpose::Release), BuildProfile::Stream, NOW)
            .unwrap();
        store
    }

    #[test]
    fn applying_a_revocation_disables_and_reports_rather_than_removing() {
        let mut store = store();
        install(&mut store, signed("community.example.theme", "1.0.0")).unwrap();

        let revocations = revocation_store(vec![RevokedModule {
            id: "community.example.theme".to_owned(),
            versions: "1.0.0".to_owned(),
            reason: RevocationReason::MaliciousCode,
            revoked_at: crate::revocation::timestamp(NOW - 3600),
            advisory: Some("https://example.org/a".to_owned()),
        }]);
        let actions = store.apply_revocations(&revocations, NOW).unwrap();

        assert_eq!(actions.len(), 1);
        assert!(actions[0].was_enabled);
        assert!(actions[0].describe().contains("malicious-code"));
        // Disabled, still present, and the reason is recorded.
        let module = store.get("community.example.theme").unwrap();
        assert!(!module.enabled);
        assert!(matches!(
            module.disabled_reason,
            Some(DisabledReason::Revoked { .. })
        ));
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn a_revoked_module_does_not_come_back_because_a_user_asked() {
        let mut store = store();
        install(&mut store, signed("community.example.theme", "1.0.0")).unwrap();
        let revocations = revocation_store(vec![RevokedModule {
            id: "community.example.theme".to_owned(),
            versions: "1.0.0".to_owned(),
            reason: RevocationReason::MaliciousCode,
            revoked_at: crate::revocation::timestamp(NOW - 3600),
            advisory: None,
        }]);
        store.apply_revocations(&revocations, NOW).unwrap();

        assert!(matches!(
            store.enable("community.example.theme"),
            Err(Error::ModuleRevoked { .. })
        ));
        assert!(!store.get("community.example.theme").unwrap().enabled);
    }

    #[test]
    fn revoking_a_key_reaches_a_module_installed_before_the_revocation() {
        let mut store = store();
        install(&mut store, signed("community.example.theme", "1.0.0")).unwrap();

        let revocations = revocation_store_with(
            Vec::new(),
            vec![RevokedKey {
                key_id: "module-2026-a".to_owned(),
                reason: RevocationReason::KeyCompromise,
                advisory: None,
            }],
        );
        let actions = store.apply_revocations(&revocations, NOW).unwrap();
        assert_eq!(actions.len(), 1);
        let module = store.get("community.example.theme").unwrap();
        assert!(!module.enabled);
        assert!(matches!(
            module.disabled_reason,
            Some(DisabledReason::KeyRevoked { .. })
        ));
    }

    #[test]
    fn a_module_signed_by_a_revoked_key_does_not_install() {
        let revocations = revocation_store_with(
            Vec::new(),
            vec![RevokedKey {
                key_id: "module-2026-a".to_owned(),
                reason: RevocationReason::KeyCompromise,
                advisory: None,
            }],
        );
        let store_ = store();
        assert!(matches!(
            store_.prepare(
                signed("community.example.theme", "1.0.0"),
                CONTENT,
                &trust(KeyPurpose::Module),
                &revocations,
                NOW,
            ),
            Err(Error::SigningKeyRevoked { .. })
        ));
    }

    #[test]
    fn a_module_with_a_missing_dependency_installs_disabled_and_recovers() {
        // madde 16c: offer to install the dependency rather than making the
        // user solve an ordering puzzle.
        let mut dependent = manifest("community.example.dependent", "1.0.0");
        dependent.kind = ModuleKind::ViewerFile;
        dependent.dependencies = vec![Dependency {
            id: "community.example.base".to_owned(),
            version: "^1.0.0".to_owned(),
            optional: false,
        }];
        let dependent = sign(dependent, CONTENT, "module-2026-a");

        let mut store = store();
        let prepared = store
            .prepare(
                dependent,
                CONTENT,
                &trust(KeyPurpose::Module),
                &RevocationStore::new(),
                NOW,
            )
            .unwrap();
        assert_eq!(prepared.missing_required().len(), 1);
        store.commit(prepared).unwrap();

        let module = store.get("community.example.dependent").unwrap();
        assert!(!module.enabled);
        assert!(module
            .disabled_reason
            .as_ref()
            .is_some_and(DisabledReason::is_recoverable));

        // The dependency turns up and the dependent comes back by itself.
        install(&mut store, signed("community.example.base", "1.4.0")).unwrap();
        assert!(store.get("community.example.dependent").unwrap().enabled);
    }

    #[test]
    fn a_dependency_outside_the_range_does_not_satisfy_it() {
        let mut dependent = manifest("community.example.dependent", "1.0.0");
        dependent.kind = ModuleKind::ViewerFile;
        dependent.dependencies = vec![Dependency {
            id: "community.example.base".to_owned(),
            version: "^2.0.0".to_owned(),
            optional: false,
        }];
        let dependent = sign(dependent, CONTENT, "module-2026-a");

        let mut store = store();
        install(&mut store, signed("community.example.base", "1.0.0")).unwrap();
        let prepared = store
            .prepare(
                dependent,
                CONTENT,
                &trust(KeyPurpose::Module),
                &RevocationStore::new(),
                NOW,
            )
            .unwrap();
        assert_eq!(prepared.missing_required().len(), 1);
    }

    #[test]
    fn removing_a_module_something_needs_is_refused_not_silently_breaking() {
        let mut dependent = manifest("community.example.dependent", "1.0.0");
        dependent.kind = ModuleKind::ViewerFile;
        dependent.dependencies = vec![Dependency {
            id: "community.example.base".to_owned(),
            version: "^1.0.0".to_owned(),
            optional: false,
        }];
        let dependent = sign(dependent, CONTENT, "module-2026-a");

        let mut store = store();
        install(&mut store, signed("community.example.base", "1.0.0")).unwrap();
        install(&mut store, dependent).unwrap();

        assert!(matches!(
            store.remove("community.example.base"),
            Err(Error::MissingDependency { .. })
        ));
        // Removing the dependent first works, then the base.
        store.remove("community.example.dependent").unwrap();
        store.remove("community.example.base").unwrap();
        assert!(store.is_empty());
    }

    #[test]
    fn an_optional_dependency_blocks_nothing() {
        let mut dependent = manifest("community.example.dependent", "1.0.0");
        dependent.kind = ModuleKind::ViewerFile;
        dependent.dependencies = vec![Dependency {
            id: "community.example.extra".to_owned(),
            version: "^1.0.0".to_owned(),
            optional: true,
        }];
        let dependent = sign(dependent, CONTENT, "module-2026-a");
        let mut store = store();
        install(&mut store, dependent).unwrap();
        assert!(store.get("community.example.dependent").unwrap().enabled);
    }

    #[test]
    fn load_order_puts_dependencies_first() {
        let mut middle = manifest("community.example.middle", "1.0.0");
        middle.kind = ModuleKind::ViewerFile;
        middle.dependencies = vec![Dependency {
            id: "community.example.base".to_owned(),
            version: "^1.0.0".to_owned(),
            optional: false,
        }];
        let mut top = manifest("community.example.top", "1.0.0");
        top.kind = ModuleKind::ViewerFile;
        top.dependencies = vec![Dependency {
            id: "community.example.middle".to_owned(),
            version: "^1.0.0".to_owned(),
            optional: false,
        }];

        let mut store = store();
        install(&mut store, sign(top, CONTENT, "module-2026-a")).unwrap();
        install(&mut store, sign(middle, CONTENT, "module-2026-a")).unwrap();
        install(&mut store, signed("community.example.base", "1.0.0")).unwrap();

        let order = store.load_order().unwrap();
        let position = |id: &str| order.iter().position(|o| o == id).unwrap_or(usize::MAX);
        assert!(position("community.example.base") < position("community.example.middle"));
        assert!(position("community.example.middle") < position("community.example.top"));
    }

    #[test]
    fn a_dependency_cycle_is_reported_and_the_store_stays_usable() {
        // Two modules that need each other. Neither can be installed second
        // without creating a cycle, and the failed install must not leave the
        // store in a state where nothing works.
        let mut a = manifest("community.example.a", "1.0.0");
        a.kind = ModuleKind::ViewerFile;
        a.dependencies = vec![Dependency {
            id: "community.example.b".to_owned(),
            version: "*".to_owned(),
            optional: false,
        }];
        let mut b = manifest("community.example.b", "1.0.0");
        b.kind = ModuleKind::ViewerFile;
        b.dependencies = vec![Dependency {
            id: "community.example.a".to_owned(),
            version: "*".to_owned(),
            optional: false,
        }];

        let mut store = store();
        install(&mut store, sign(a, CONTENT, "module-2026-a")).unwrap();
        let err = install(&mut store, sign(b, CONTENT, "module-2026-a")).unwrap_err();
        assert!(matches!(err, Error::DependencyCycle(_)), "{err}");

        // The cycle was rolled back: `a` is still there and the order computes.
        assert_eq!(store.len(), 1);
        store.load_order().unwrap();
    }

    #[test]
    fn disable_and_enable_round_trip() {
        let mut store = store();
        install(&mut store, signed("community.example.theme", "1.0.0")).unwrap();
        store.disable("community.example.theme").unwrap();
        assert_eq!(
            store
                .get("community.example.theme")
                .unwrap()
                .disabled_reason,
            Some(DisabledReason::User)
        );
        store.enable("community.example.theme").unwrap();
        assert!(store.get("community.example.theme").unwrap().enabled);
    }

    #[test]
    fn operations_on_an_unknown_id_say_so() {
        let mut store = store();
        assert!(matches!(
            store.remove("nope.nope"),
            Err(Error::ModuleNotInstalled(_))
        ));
        assert!(matches!(
            store.enable("nope.nope"),
            Err(Error::ModuleNotInstalled(_))
        ));
        assert!(matches!(
            store.disable("nope.nope"),
            Err(Error::ModuleNotInstalled(_))
        ));
        assert!(matches!(
            store.reorder("nope.nope", 0),
            Err(Error::ModuleNotInstalled(_))
        ));
    }

    #[test]
    fn a_prepared_install_carries_what_the_prompt_needs() {
        let mut m = manifest("community.example.theme", "1.0.0");
        m.license = None;
        let m = sign(m, CONTENT, "module-2026-a");
        let store_ = store();
        let prepared = store_
            .prepare(
                m,
                CONTENT,
                &trust(KeyPurpose::Module),
                &RevocationStore::new(),
                NOW,
            )
            .unwrap();
        // A declarative module requests nothing, which is the v1 shape.
        assert!(prepared.permissions().is_empty());
        assert_eq!(prepared.signed_by(), "module-2026-a");
        assert!(prepared.replaces().is_none());
        assert!(prepared.notes().iter().any(|n| n.code == "no-license"));
    }

    #[test]
    fn an_update_reports_what_it_replaces() {
        let mut store = store();
        install(&mut store, signed("community.example.theme", "1.0.0")).unwrap();
        let prepared = store
            .prepare(
                signed("community.example.theme", "1.1.0"),
                CONTENT,
                &trust(KeyPurpose::Module),
                &RevocationStore::new(),
                NOW,
            )
            .unwrap();
        assert_eq!(
            prepared.replaces().map(ToString::to_string).as_deref(),
            Some("1.0.0")
        );
    }

    #[test]
    fn a_store_round_trips_and_refuses_the_wrong_build() {
        let mut store = store();
        install(&mut store, signed("community.example.theme", "1.0.0")).unwrap();
        let text = store.to_json().unwrap();

        let back = ModuleStore::from_json(&text, BuildProfile::Stream).unwrap();
        assert_eq!(back.len(), 1);
        assert_eq!(
            back.get("community.example.theme").unwrap().signed_by,
            "module-2026-a"
        );

        // An Edu build must not read a Stream store: it would carry modules
        // into a build that is not allowed to have them (madde 22).
        assert!(matches!(
            ModuleStore::from_json(&text, BuildProfile::Edu),
            Err(Error::ModuleNotAllowedInBuild { .. })
        ));
    }

    #[test]
    fn enabled_of_kind_filters_both_ways() {
        let mut store = store();
        install(&mut store, signed("community.example.theme", "1.0.0")).unwrap();
        let mut viewer = manifest("community.example.viewer", "1.0.0");
        viewer.kind = ModuleKind::ViewerFile;
        install(&mut store, sign(viewer, CONTENT, "module-2026-a")).unwrap();

        assert_eq!(store.enabled_of_kind(ModuleKind::Theme).len(), 1);
        assert_eq!(store.enabled_of_kind(ModuleKind::ViewerFile).len(), 1);
        store.disable("community.example.theme").unwrap();
        assert_eq!(store.enabled_of_kind(ModuleKind::Theme).len(), 0);
        assert_eq!(store.enabled().len(), 1);
    }
}
