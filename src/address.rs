// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 EON contributors
//
// Additional permission under GNU GPL version 3 section 7:
// see LICENSE-EXCEPTION.md (EON Module ABI Exception 1.0).

//! Turning what a person pasted into request URLs.
//!
//! People paste `https://host/manifest.json`, or the bare host, or a
//! `stremio://` link copied from somewhere else. All three mean the same addon,
//! and the base URL is what every later request is built from.
//!
//! One rule is load-bearing rather than cosmetic: **the addon address never
//! leaves the device and is never shown to a module** (see `docs/module-abi.md`
//! in `eon-stream-spec`). A configured addon URL can carry credentials in its
//! path, so it is not logged, not sent anywhere, and not included in errors.

use crate::{Error, Result};

/// A validated addon address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddonAddress {
    /// Base URL with no trailing slash. Requests are built by appending to it.
    base: String,
}

impl AddonAddress {
    /// Parse what the user supplied.
    ///
    /// Accepts `https://`, `http://` (loopback only), `stremio://`, and a bare
    /// host with optional path. A trailing `/manifest.json` is stripped.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidAddress`] when the text is empty, has no host, or asks
    /// for plain HTTP to somewhere other than loopback.
    pub fn parse(input: &str) -> Result<Self> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Err(Error::InvalidAddress("address is empty".into()));
        }

        // stremio:// links carry the same shape; treat them as https.
        let (scheme, rest) = match trimmed.split_once("://") {
            Some(("stremio", rest)) => ("https", rest),
            Some((scheme, rest)) => (scheme, rest),
            None => ("https", trimmed),
        };

        if !matches!(scheme, "https" | "http") {
            return Err(Error::InvalidAddress(format!(
                "unsupported scheme '{scheme}'"
            )));
        }

        let rest = rest.trim_end_matches('/');
        if rest.is_empty() {
            return Err(Error::InvalidAddress("address has no host".into()));
        }

        let host = rest.split(['/', '?', '#']).next().unwrap_or(rest);
        if host.is_empty() {
            return Err(Error::InvalidAddress("address has no host".into()));
        }

        if scheme == "http" && !is_loopback(host) {
            return Err(Error::InvalidAddress(
                "plain HTTP is only accepted for loopback addresses; use https".into(),
            ));
        }

        // Drop a query or fragment: neither is part of an addon's base path.
        let path_end = rest.find(['?', '#']).unwrap_or(rest.len());
        let without_query = &rest[..path_end];
        let without_manifest = without_query
            .strip_suffix("/manifest.json")
            .unwrap_or(without_query)
            .trim_end_matches('/');

        Ok(Self {
            base: format!("{scheme}://{without_manifest}"),
        })
    }

    /// The manifest URL.
    #[must_use]
    pub fn manifest_url(&self) -> String {
        format!("{}/manifest.json", self.base)
    }

    /// URL for a resource request: `{base}/{resource}/{type}/{id}.json`.
    #[must_use]
    pub fn resource_url(&self, resource: &str, content_type: &str, id: &str) -> String {
        format!(
            "{}/{}/{}/{}.json",
            self.base,
            encode_segment(resource),
            encode_segment(content_type),
            encode_segment(id)
        )
    }

    /// URL for a catalogue request with extra parameters.
    ///
    /// Extra parameters go in their own path segment as `key=value` pairs joined
    /// by `&`, which is how the protocol carries them. An empty list produces
    /// the plain resource URL.
    #[must_use]
    pub fn catalog_url(&self, content_type: &str, id: &str, extra: &[(&str, &str)]) -> String {
        if extra.is_empty() {
            return self.resource_url("catalog", content_type, id);
        }
        let encoded = extra
            .iter()
            .map(|(k, v)| format!("{}={}", encode_segment(k), encode_segment(v)))
            .collect::<Vec<_>>()
            .join("&");
        format!(
            "{}/catalog/{}/{}/{}.json",
            self.base,
            encode_segment(content_type),
            encode_segment(id),
            encoded
        )
    }

    /// URL for any resource request with extra parameters.
    ///
    /// The protocol puts extras in their own path segment for every resource, not
    /// just catalogues — which is how a subtitles request carries the file name
    /// and hash it should match on.
    #[must_use]
    pub fn resource_url_with_extra(
        &self,
        resource: &str,
        content_type: &str,
        id: &str,
        extra: &[(&str, &str)],
    ) -> String {
        if extra.is_empty() {
            return self.resource_url(resource, content_type, id);
        }
        let encoded = extra
            .iter()
            .map(|(k, v)| format!("{}={}", encode_segment(k), encode_segment(v)))
            .collect::<Vec<_>>()
            .join("&");
        format!(
            "{}/{}/{}/{}/{}.json",
            self.base,
            encode_segment(resource),
            encode_segment(content_type),
            encode_segment(id),
            encoded
        )
    }

    /// The base URL.
    ///
    /// Treat the result as secret: it may contain configuration credentials, so
    /// it must not be logged, displayed, or handed to a module.
    #[must_use]
    pub fn base(&self) -> &str {
        &self.base
    }
}

impl serde::Serialize for AddonAddress {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.base)
    }
}

impl<'de> serde::Deserialize<'de> for AddonAddress {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::parse(&raw).map_err(serde::de::Error::custom)
    }
}

/// Whether a host is loopback, and therefore allowed over plain HTTP.
fn is_loopback(host: &str) -> bool {
    let without_port = host.rsplit_once(':').map_or(host, |(h, _)| h);
    matches!(without_port, "localhost" | "127.0.0.1" | "[::1]" | "::1")
        || without_port.starts_with("127.")
}

/// Percent-encode the characters that would otherwise change a URL's structure.
///
/// Deliberately conservative rather than strict: addon ids in the wild contain
/// `:` and `,` and are sent literally by other clients, so encoding them would
/// break addons that work elsewhere. Only what actually breaks parsing is
/// escaped.
fn encode_segment(segment: &str) -> String {
    let mut out = String::with_capacity(segment.len());
    for byte in segment.bytes() {
        match byte {
            b'%' | b'?' | b'#' | b'/' | b'\\' | b' ' | b'"' | b'<' | b'>' | b'{' | b'}' | b'|'
            | b'^' | b'`' => {
                out.push('%');
                out.push(hex_digit(byte >> 4));
                out.push(hex_digit(byte & 0x0f));
            }
            b if b.is_ascii_control() || b >= 0x80 => {
                out.push('%');
                out.push(hex_digit(b >> 4));
                out.push(hex_digit(b & 0x0f));
            }
            b => out.push(b as char),
        }
    }
    out
}

/// Uppercase hex digit for a value in `0..=15`.
///
/// Values above 15 cannot occur: every caller masks to four bits.
fn hex_digit(nibble: u8) -> char {
    match nibble {
        0..=9 => (b'0' + nibble) as char,
        10..=15 => (b'A' + (nibble - 10)) as char,
        _ => '0',
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn accepts_the_three_shapes_people_paste() {
        for input in [
            "https://addon.example.org/manifest.json",
            "https://addon.example.org/",
            "addon.example.org",
            "stremio://addon.example.org/manifest.json",
        ] {
            let address = AddonAddress::parse(input).unwrap();
            assert_eq!(
                address.manifest_url(),
                "https://addon.example.org/manifest.json",
                "input: {input}"
            );
        }
    }

    #[test]
    fn keeps_a_configuration_path() {
        let address =
            AddonAddress::parse("https://addon.example.org/c/abc123/manifest.json").unwrap();
        assert_eq!(
            address.manifest_url(),
            "https://addon.example.org/c/abc123/manifest.json"
        );
        assert_eq!(
            address.resource_url("stream", "movie", "tt0111161"),
            "https://addon.example.org/c/abc123/stream/movie/tt0111161.json"
        );
    }

    #[test]
    fn rejects_plain_http_off_loopback() {
        assert!(AddonAddress::parse("http://addon.example.org").is_err());
        assert!(AddonAddress::parse("http://127.0.0.1:11470").is_ok());
        assert!(AddonAddress::parse("http://localhost:8080").is_ok());
    }

    #[test]
    fn rejects_nonsense() {
        assert!(AddonAddress::parse("").is_err());
        assert!(AddonAddress::parse("   ").is_err());
        assert!(AddonAddress::parse("ftp://addon.example.org").is_err());
        assert!(AddonAddress::parse("https://").is_err());
    }

    #[test]
    fn builds_catalog_urls_with_extra() {
        let address = AddonAddress::parse("https://addon.example.org").unwrap();
        assert_eq!(
            address.catalog_url("movie", "top", &[]),
            "https://addon.example.org/catalog/movie/top.json"
        );
        assert_eq!(
            address.catalog_url("movie", "top", &[("search", "blade runner")]),
            "https://addon.example.org/catalog/movie/top/search=blade%20runner.json"
        );
        assert_eq!(
            address.catalog_url("movie", "top", &[("genre", "Sci-Fi"), ("skip", "100")]),
            "https://addon.example.org/catalog/movie/top/genre=Sci-Fi&skip=100.json"
        );
    }

    #[test]
    fn leaves_ids_that_other_clients_send_literally() {
        let address = AddonAddress::parse("https://addon.example.org").unwrap();
        assert_eq!(
            address.resource_url("stream", "series", "tt0903747:1:1"),
            "https://addon.example.org/stream/series/tt0903747:1:1.json"
        );
    }

    #[test]
    fn escapes_what_would_break_the_url() {
        let address = AddonAddress::parse("https://addon.example.org").unwrap();
        assert_eq!(
            address.resource_url("meta", "movie", "a/b?c#d"),
            "https://addon.example.org/meta/movie/a%2Fb%3Fc%23d.json"
        );
    }
}
