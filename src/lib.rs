// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 EON contributors
//
// Additional permission under GNU GPL version 3 section 7:
// see LICENSE-EXCEPTION.md (EON Module ABI Exception 1.0).

//! # EON Stream core
//!
//! The parts of EON Stream that decide *what* to do. Moving bytes is `eon-stream-engine`;
//! drawing pixels is `eon-stream-app`.
//!
//! This crate has no user interface, no player, and no torrent engine. A dependency
//! on a GUI toolkit here is a design failure, not a convenience.
//!
//! ## Status
//!
//! Faz 0 skeleton. The module layout below is the intended shape; most of it is not
//! written yet. Two decisions are still open and are tracked in the project plan:
//! the protocol layer (madde 1) and the sandbox for code-executing modules (madde 4).
//!
//! ## Invariants this crate must uphold
//!
//! * First-party modules use the same API as community modules (madde 3). Enforced in
//!   CI, not merely intended.
//! * Nothing is granted to a module implicitly: no ambient filesystem access, no
//!   ambient network access. See `docs/module-abi.md` in `eon-stream-spec`.
//! * An addon URL never leaves the device and is never exposed to a module: a
//!   configured addon URL can carry credentials.
//! * A revoked or downgraded version is refused, and the user is told why
//!   (madde 34, 39).
//! * No telemetry. Not off-by-default -- absent (madde 36).

#![forbid(unsafe_code)]

/// Module manifests, validation against the `eon-stream-spec` schemas, and the
/// capability model.
pub mod manifest {}

/// Install, update, remove and dependency resolution for modules; permission
/// enforcement at the Module ABI boundary.
pub mod modules {}

/// Remote addon protocol client: manifest, catalog, meta, stream, subtitles.
/// Per-addon failure isolation lives here -- one bad addon must not empty a
/// merged catalogue.
pub mod addons {}

/// Ed25519 signature verification and the revocation list.
///
/// Revocation is not optional: a signature without revocation proves who shipped
/// a malicious version, it does not stop it.
pub mod signing {}

/// User settings and their persistence. Local only.
pub mod settings {}

/// Update checks and the rules that make the updater safe: signature required,
/// version never goes backwards, staged rollout, emergency stop (madde 39).
pub mod updater {}

/// Errors surfaced to the host application.
pub mod error {}
