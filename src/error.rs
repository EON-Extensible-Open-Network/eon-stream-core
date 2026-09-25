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
