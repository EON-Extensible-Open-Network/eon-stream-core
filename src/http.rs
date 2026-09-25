// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 EON contributors
//
// Additional permission under GNU GPL version 3 section 7:
// see LICENSE-EXCEPTION.md (EON Module ABI Exception 1.0).

//! The transport boundary.
//!
//! This crate performs no I/O itself. It asks an [`HttpClient`] for bytes, and
//! the host supplies one. That split buys three things the project needs:
//!
//! * The compatibility suite runs against **recorded fixtures** and never
//!   depends on third-party uptime (madde 1). A suite that goes red because
//!   somebody else's server had a bad afternoon stops being trusted, and an
//!   untrusted suite is worse than none.
//! * The library pulls in no network stack, so it stays small and its
//!   dependency licences stay boring.
//! * The host decides on the async runtime, proxying and certificate policy.
//!   `eon-stream-core` has no opinion and no GUI dependency.

use std::collections::HashMap;

/// Limits every implementation is expected to honour.
///
/// These are not suggestions: a hostile or merely broken addon must not be able
/// to hang the application or exhaust its memory (see `SECURITY.md`).
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// How long a single request may take, in milliseconds.
    pub timeout_ms: u64,
    /// Largest response body accepted, in bytes.
    pub max_body_bytes: usize,
    /// How many redirects to follow before giving up.
    pub max_redirects: u8,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            timeout_ms: 15_000,
            max_body_bytes: 8 * 1024 * 1024,
            max_redirects: 5,
        }
    }
}

/// What an addon answered.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    /// HTTP status code.
    pub status: u16,
    /// Raw response body.
    pub body: Vec<u8>,
}

/// A transport-level failure: the request did not produce a response at all.
#[derive(Debug, Clone)]
pub struct HttpError {
    /// Human-readable description.
    ///
    /// Implementations must not put the request URL in here. A configured addon
    /// URL can carry credentials in its path, and errors end up in logs and bug
    /// reports.
    pub message: String,
}

impl HttpError {
    /// Build a transport error from anything printable.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

/// Fetches bytes over HTTP.
///
/// Implementations must enforce [`Limits`] and must not follow a redirect to a
/// non-HTTPS destination.
pub trait HttpClient {
    /// Perform a GET request.
    ///
    /// # Errors
    ///
    /// Returns [`HttpError`] when no response was obtained. A response with a
    /// non-success status is **not** an error here: it is returned so the caller
    /// can report the status the addon actually sent.
    fn get(&self, url: &str) -> std::result::Result<HttpResponse, HttpError>;

    /// The limits this client enforces.
    fn limits(&self) -> Limits {
        Limits::default()
    }
}

impl<T: HttpClient + ?Sized> HttpClient for &T {
    fn get(&self, url: &str) -> std::result::Result<HttpResponse, HttpError> {
        (**self).get(url)
    }

    fn limits(&self) -> Limits {
        (**self).limits()
    }
}

/// An [`HttpClient`] that answers from a fixed table instead of the network.
///
/// This is the backbone of the compatibility suite: record an addon's responses
/// once, pin them, and the suite becomes deterministic and offline.
#[derive(Debug, Default, Clone)]
pub struct FixtureClient {
    responses: HashMap<String, HttpResponse>,
    limits: Limits,
}

impl FixtureClient {
    /// An empty fixture set. Every request fails until something is inserted.
    #[must_use]
    pub fn new() -> Self {
        Self {
            responses: HashMap::new(),
            limits: Limits::default(),
        }
    }

    /// Answer `url` with HTTP 200 and this body.
    #[must_use]
    pub fn with_json(mut self, url: impl Into<String>, body: impl Into<String>) -> Self {
        self.responses.insert(
            url.into(),
            HttpResponse {
                status: 200,
                body: body.into().into_bytes(),
            },
        );
        self
    }

    /// Answer `url` with an arbitrary status and body.
    #[must_use]
    pub fn with_response(
        mut self,
        url: impl Into<String>,
        status: u16,
        body: impl Into<String>,
    ) -> Self {
        self.responses.insert(
            url.into(),
            HttpResponse {
                status,
                body: body.into().into_bytes(),
            },
        );
        self
    }

    /// Every URL this fixture set knows about, for assertions about which
    /// requests a test expected.
    #[must_use]
    pub fn known_urls(&self) -> Vec<&str> {
        let mut urls: Vec<&str> = self.responses.keys().map(String::as_str).collect();
        urls.sort_unstable();
        urls
    }
}

impl HttpClient for FixtureClient {
    fn get(&self, url: &str) -> std::result::Result<HttpResponse, HttpError> {
        self.responses.get(url).cloned().ok_or_else(|| {
            // Deliberately says nothing about what was requested -- not even the
            // path. An addon's configuration credentials live *in the path*
            // (`/c/<token>/manifest.json`), so echoing a path leaks exactly what
            // echoing a URL would. A test caught this; the fixture client holds
            // the same line as the real one, and `known_urls` is there for
            // debugging a missing fixture.
            HttpError::new("no fixture recorded for this request")
        })
    }

    fn limits(&self) -> Limits {
        self.limits
    }
}
