// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 EON contributors
//
// Additional permission under GNU GPL version 3 section 7:
// see LICENSE-EXCEPTION.md (EON Module ABI Exception 1.0).

//! # EON Stream core
//!
//! The parts of EON Stream that decide *what* to do. Moving bytes is
//! `eon-stream-engine`; drawing pixels is `eon-stream-app`.
//!
//! This crate has no user interface, no player, no torrent engine, and performs
//! **no I/O of its own** — it asks an [`HttpClient`] for bytes. A dependency on
//! a GUI toolkit here is a design failure, not a convenience.
//!
//! ## What works today
//!
//! **Addons.** Resolve an address, fetch and validate the manifest, list
//! catalogues, page through one, fetch metadata, and collect playable sources
//! across every installed addon.
//!
//! **Modules.** Install, update, remove, enable and order them, with Ed25519
//! signature verification against a rotating trust set, version-scoped
//! revocation, dependency resolution and a load order ([`modules`]).
//!
//! **Themes.** Declarative colour, type and spacing documents that carry no
//! code, resolved to flat tokens and checked against WCAG contrast
//! requirements ([`theme`]).
//!
//! **Settings, updates and messages.** Typed settings with no reporting key
//! anywhere in them ([`settings`]), a release checker that refuses a
//! downgrade ([`update`]), and Turkish and English message catalogues
//! ([`i18n`]).
//!
//! ```no_run
//! use eon_stream_core::{AddonClient, AddonRegistry, http::FixtureClient};
//!
//! // In the application this is a real HTTP client; in tests it is a fixture
//! // set, which is how the compatibility suite avoids depending on anyone
//! // else's uptime.
//! let http = FixtureClient::new();
//! let client = AddonClient::new(&http);
//! let mut registry = AddonRegistry::new();
//!
//! let addon = client.install(&mut registry, "https://addon.example.org/manifest.json")?;
//! for catalog in &addon.manifest.catalogs {
//!     let page = client.catalog(&addon, &catalog.content_type, &catalog.id, &[])?;
//!     for item in page {
//!         println!("{}", item.display_name());
//!     }
//! }
//!
//! let found = client.streams_from_all(&registry, "movie", "tt0111161");
//! println!("{} sources, {} addons failed", found.total(), found.failures.len());
//! # Ok::<(), eon_stream_core::Error>(())
//! ```
//!
//! ## Invariants this crate upholds
//!
//! * **An addon address never leaves the device** and is never exposed to a
//!   module. A configured addon URL can carry credentials in its path, so it is
//!   not logged, not put in errors, and not present in [`AddonSummary`].
//! * **A resource the manifest does not declare is never requested.**
//! * **Failures are per addon.** One broken addon never empties a merged result
//!   (madde 1).
//! * **Addon responses are untrusted input.** Status and size are checked;
//!   malformed data is an ordinary error, never a panic. `unwrap` and `panic`
//!   are denied crate-wide: a panic in the module manager takes the whole
//!   application down with it.
//! * **No telemetry.** Not off-by-default — absent (madde 36).
//!
//! * **Nothing is installed unsigned**, first-party modules included
//!   (madde 3), and nothing executes: v1 installs declarative modules only,
//!   because there is no sandbox yet and a security claim without one would
//!   not be honest (madde 4).
//! * **A version never goes backwards**, for modules or for the application
//!   itself (madde 39).
//! * **This crate verifies and never signs.** The signing half of the
//!   dependency is switched off; a client that can also sign is a client
//!   whose compromise produces valid artefacts.
//!
//! ## Still to come
//!
//! The module sandbox — wasmtime with capability host functions, against an
//! isolated webview — which is madde 4 and does not block v1. Until it
//! exists, [`modules`] refuses a `wasm` module by name rather than pretending
//! not to recognise it.

#![forbid(unsafe_code)]

pub mod address;
pub mod client;
pub mod error;
pub mod health;
pub mod history;
pub mod http;
pub mod i18n;
pub mod manifest;
pub mod module;
pub mod modules;
pub mod ranking;
pub mod registry;
pub mod revocation;
pub mod semver;
pub(crate) mod serde_lax;
pub mod settings;
pub mod signature;
pub mod theme;
pub mod time;
pub mod types;
pub mod update;

pub use address::AddonAddress;
pub use client::{AddonClient, Merged};
pub use error::{AddonFailure, Error, Result};
pub use health::{AddonHealth, HealthTracker};
pub use history::{WatchEntry, WatchHistory};
pub use http::{HttpClient, HttpResponse, Limits};
pub use i18n::{Catalog as MessageCatalog, Messages};
pub use manifest::{AddonManifest, Catalog, Resource, ADDON_API_MAJOR};
pub use module::{
    BuildProfile, ModuleKind, ModuleManifest, Permission, Platform, RuntimeKind, SignatureEnvelope,
    MODULE_API_MAJOR, MODULE_API_MINOR,
};
pub use modules::{DisabledReason, InstalledModule, ModuleStore, PreparedInstall};
pub use ranking::{
    rank, Codec, DynamicRange, RankedStream, RankingPreferences, Resolution, StreamFacts,
};
pub use registry::{AddonRegistry, AddonSummary, InstalledAddon};
pub use revocation::{
    RevocationAction, RevocationFreshness, RevocationList, RevocationReason, RevocationStatus,
    RevocationStore,
};
pub use semver::{Version, VersionRange};
pub use settings::{Settings, UpdateChannel};
pub use signature::{Artefact, KeyPurpose, Subject, TrustFreshness, TrustStore, TrustedKey};
pub use theme::{ColorToken, ResolvedTheme, ThemeBase, ThemeDocument};
pub use types::{
    Meta, MetaPreview, ProxyHeaders, Stream, StreamBehaviorHints, StreamSource, Subtitle,
    SubtitleMatch, Video,
};
pub use update::{Arch, Artifact, ReleaseManifest, UpdateCheck, UpdateDecision};
