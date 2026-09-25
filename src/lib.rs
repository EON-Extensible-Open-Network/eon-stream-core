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
//! Adding an addon and browsing it: resolve an address, fetch and validate the
//! manifest, list catalogues, page through a catalogue, fetch metadata, and
//! collect playable sources across every installed addon.
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
//! ## Still to come
//!
//! Module management, signature verification and revocation, settings and the
//! updater. Their decisions are open in the plan: the protocol layer question
//! (madde 1) is being answered by this implementation, and the module sandbox
//! (madde 4) does not block v1.

#![forbid(unsafe_code)]

pub mod address;
pub mod client;
pub mod error;
pub mod http;
pub mod manifest;
pub mod registry;
pub(crate) mod serde_lax;
pub mod types;

pub use address::AddonAddress;
pub use client::{AddonClient, Merged};
pub use error::{AddonFailure, Error, Result};
pub use http::{HttpClient, HttpResponse, Limits};
pub use manifest::{AddonManifest, Catalog, Resource, ADDON_API_MAJOR};
pub use registry::{AddonRegistry, AddonSummary, InstalledAddon};
pub use types::{Meta, MetaPreview, Stream, StreamSource, Subtitle, Video};
