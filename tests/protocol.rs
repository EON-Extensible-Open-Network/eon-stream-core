// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 EON contributors

//! The addon protocol compatibility suite.
//!
//! Every response here is a **recorded fixture**, pinned in `tests/fixtures/`.
//! Nothing in this file touches the network, on purpose: a suite that goes red
//! because somebody else's server had a bad afternoon stops being trusted, and
//! an untrusted suite is worse than none (madde 1).
//!
//! A separate, optional job may run against live endpoints. It is allowed to
//! fail and never blocks a release.

// Tests assert by panicking; that is what a test harness is for.
#![allow(clippy::unwrap_used, clippy::panic)]

use eon_stream_core::{http::FixtureClient, AddonClient, AddonRegistry, Error, StreamSource};

const MOVIE_BASE: &str = "https://movies.test.invalid";
const SERIES_BASE: &str = "https://series.test.invalid";

const MOVIE_MANIFEST: &str = include_str!("fixtures/movie-addon.manifest.json");
const MOVIE_CATALOG_TOP: &str = include_str!("fixtures/movie-addon.catalog-top.json");
const MOVIE_CATALOG_SEARCH: &str = include_str!("fixtures/movie-addon.catalog-search.json");
const MOVIE_META: &str = include_str!("fixtures/movie-addon.meta.json");
const MOVIE_STREAMS: &str = include_str!("fixtures/movie-addon.streams.json");
const SERIES_MANIFEST: &str = include_str!("fixtures/series-addon.manifest.json");
const SERIES_META: &str = include_str!("fixtures/series-addon.meta.json");

/// A fixture set covering the movie addon end to end.
fn movie_addon() -> FixtureClient {
    FixtureClient::new()
        .with_json(format!("{MOVIE_BASE}/manifest.json"), MOVIE_MANIFEST)
        .with_json(
            format!("{MOVIE_BASE}/catalog/movie/top.json"),
            MOVIE_CATALOG_TOP,
        )
        .with_json(
            format!("{MOVIE_BASE}/catalog/movie/top/search=blade%20runner.json"),
            MOVIE_CATALOG_SEARCH,
        )
        .with_json(
            format!("{MOVIE_BASE}/meta/movie/tt0111161.json"),
            MOVIE_META,
        )
        .with_json(
            format!("{MOVIE_BASE}/stream/movie/tt0111161.json"),
            MOVIE_STREAMS,
        )
}

#[test]
fn installs_an_addon_from_a_pasted_address() {
    let http = movie_addon();
    let client = AddonClient::new(&http);
    let mut registry = AddonRegistry::new();

    let addon = client
        .install(&mut registry, &format!("{MOVIE_BASE}/manifest.json"))
        .unwrap();

    assert_eq!(addon.id(), "org.eon.test.movies");
    assert_eq!(addon.manifest.name, "Test Movies");
    assert_eq!(addon.manifest.catalogs.len(), 2);
    assert_eq!(registry.len(), 1);
    assert!(addon.enabled);
}

#[test]
fn the_three_address_shapes_install_the_same_addon() {
    for address in [
        MOVIE_BASE.to_owned(),
        format!("{MOVIE_BASE}/"),
        format!("{MOVIE_BASE}/manifest.json"),
        MOVIE_BASE.replace("https://", "stremio://"),
    ] {
        let http = movie_addon();
        let client = AddonClient::new(&http);
        let mut registry = AddonRegistry::new();
        client.install(&mut registry, &address).unwrap();
        assert_eq!(registry.len(), 1, "address: {address}");
    }
}

#[test]
fn installing_twice_is_refused() {
    let http = movie_addon();
    let client = AddonClient::new(&http);
    let mut registry = AddonRegistry::new();

    client.install(&mut registry, MOVIE_BASE).unwrap();
    let err = client.install(&mut registry, MOVIE_BASE).unwrap_err();

    assert!(matches!(err, Error::AlreadyInstalled(_)));
    assert_eq!(registry.len(), 1);
}

#[test]
fn browses_a_catalogue() {
    let http = movie_addon();
    let client = AddonClient::new(&http);
    let mut registry = AddonRegistry::new();
    let addon = client.install(&mut registry, MOVIE_BASE).unwrap();

    let page = client.catalog(&addon, "movie", "top", &[]).unwrap();

    assert_eq!(page.len(), 3);
    assert_eq!(page[0].display_name(), "The Shawshank Redemption");
    // An entry with no name must still be displayable rather than blank.
    assert_eq!(page[2].display_name(), "tt0071562");
}

#[test]
fn search_reaches_the_extra_parameter_path() {
    let http = movie_addon();
    let client = AddonClient::new(&http);
    let mut registry = AddonRegistry::new();
    let addon = client.install(&mut registry, MOVIE_BASE).unwrap();

    let page = client
        .catalog(&addon, "movie", "top", &[("search", "blade runner")])
        .unwrap();

    assert_eq!(page.len(), 1);
    assert_eq!(page[0].display_name(), "Blade Runner");
}

#[test]
fn reads_metadata() {
    let http = movie_addon();
    let client = AddonClient::new(&http);
    let mut registry = AddonRegistry::new();
    let addon = client.install(&mut registry, MOVIE_BASE).unwrap();

    let meta = client.meta(&addon, "movie", "tt0111161").unwrap();

    assert_eq!(meta.display_name(), "The Shawshank Redemption");
    assert_eq!(meta.genres, ["Drama"]);
    assert_eq!(meta.runtime.as_deref(), Some("142 min"));
}

#[test]
fn classifies_every_kind_of_stream_and_tolerates_a_useless_one() {
    let http = movie_addon();
    let client = AddonClient::new(&http);
    let mut registry = AddonRegistry::new();
    let addon = client.install(&mut registry, MOVIE_BASE).unwrap();

    let streams = client.streams(&addon, "movie", "tt0111161").unwrap();
    assert_eq!(streams.len(), 5);

    assert!(matches!(streams[0].source(), Some(StreamSource::Direct(_))));
    match streams[1].source() {
        Some(StreamSource::Torrent {
            info_hash,
            file_idx,
        }) => {
            assert_eq!(info_hash.len(), 40);
            assert_eq!(file_idx, Some(0));
        }
        other => panic!("expected a torrent source, got {other:?}"),
    }
    assert!(matches!(
        streams[2].source(),
        Some(StreamSource::YouTube("6hB3S9bIaco"))
    ));
    assert!(matches!(
        streams[3].source(),
        Some(StreamSource::External(_))
    ));
    // A stream object with nothing playable in it happens, and must not crash.
    assert!(streams[4].source().is_none());

    // Newlines in a title would break a single-line list.
    assert!(!streams[0].display_label().contains('\n'));
}

#[test]
fn a_resource_the_manifest_does_not_declare_is_never_requested() {
    let http = movie_addon();
    let client = AddonClient::new(&http);
    let mut registry = AddonRegistry::new();
    let addon = client.install(&mut registry, MOVIE_BASE).unwrap();

    // The movie addon declares no `subtitles` resource. The fixture set has no
    // subtitles URL either, so a transport error would prove a request was sent.
    let err = client.subtitles(&addon, "movie", "tt0111161").unwrap_err();

    match err {
        Error::ResourceNotOffered {
            resource,
            content_type,
            ..
        } => {
            assert_eq!(resource, "subtitles");
            assert_eq!(content_type, "movie");
        }
        other => panic!("expected ResourceNotOffered, got {other:?}"),
    }
}

#[test]
fn one_failing_addon_does_not_empty_the_result() {
    let http = movie_addon()
        .with_json(format!("{SERIES_BASE}/manifest.json"), SERIES_MANIFEST)
        .with_response(
            format!("{SERIES_BASE}/stream/series/tt0111161.json"),
            503,
            "upstream down",
        );
    let client = AddonClient::new(&http);
    let mut registry = AddonRegistry::new();
    client.install(&mut registry, MOVIE_BASE).unwrap();
    client.install(&mut registry, SERIES_BASE).unwrap();

    // Asked as a movie: only the movie addon declares the type, so the series
    // addon is not even a candidate.
    let found = client.streams_from_all(&registry, "movie", "tt0111161");
    assert_eq!(found.total(), 5);
    assert!(found.failures.is_empty());

    // Asked as a series: the series addon is the only candidate, and it fails.
    let failed = client.streams_from_all(&registry, "series", "tt0111161");
    assert_eq!(failed.total(), 0);
    assert_eq!(failed.failures.len(), 1);
    assert!(failed.all_failed());
    assert_eq!(failed.failures[0].addon_name, "Test Series");
    assert!(matches!(
        failed.failures[0].error,
        Error::HttpStatus { status: 503 }
    ));
}

#[test]
fn id_prefixes_keep_us_from_asking_pointless_questions() {
    let http = movie_addon();
    let client = AddonClient::new(&http);
    let mut registry = AddonRegistry::new();
    client.install(&mut registry, MOVIE_BASE).unwrap();

    // The movie addon declares idPrefixes ["tt"], so a Kitsu-style id is not
    // its business. No candidate means no request and no failure.
    let found = client.streams_from_all(&registry, "movie", "kitsu:12345");
    assert_eq!(found.total(), 0);
    assert!(
        found.failures.is_empty(),
        "a skipped addon must not be reported as failing"
    );
}

#[test]
fn malformed_json_is_an_error_not_a_panic() {
    let http =
        FixtureClient::new().with_json(format!("{MOVIE_BASE}/manifest.json"), "{ not json at all");
    let client = AddonClient::new(&http);
    let mut registry = AddonRegistry::new();

    let err = client.install(&mut registry, MOVIE_BASE).unwrap_err();

    assert!(matches!(err, Error::MalformedJson { .. }));
    assert!(registry.is_empty());
}

#[test]
fn a_manifest_missing_required_fields_is_refused() {
    let http = FixtureClient::new().with_json(
        format!("{MOVIE_BASE}/manifest.json"),
        r#"{"id":"x.y","version":"1.0.0","name":"No Resources","resources":[],"types":["movie"]}"#,
    );
    let client = AddonClient::new(&http);
    let mut registry = AddonRegistry::new();

    let err = client.install(&mut registry, MOVIE_BASE).unwrap_err();

    assert!(matches!(err, Error::InvalidManifest(_)));
    assert!(registry.is_empty());
}

#[test]
fn an_addon_targeting_a_future_api_major_is_refused_with_a_reason() {
    let http = FixtureClient::new().with_json(
        format!("{MOVIE_BASE}/manifest.json"),
        r#"{"id":"x.y","version":"1.0.0","name":"From The Future",
            "resources":["catalog"],"types":["movie"],"eon":{"minApi":"9.0"}}"#,
    );
    let client = AddonClient::new(&http);
    let mut registry = AddonRegistry::new();

    let err = client.install(&mut registry, MOVIE_BASE).unwrap_err();

    match err {
        Error::UnsupportedApiVersion { wanted, ours } => {
            assert_eq!(wanted, 9);
            assert_eq!(ours, eon_stream_core::ADDON_API_MAJOR);
        }
        other => panic!("expected UnsupportedApiVersion, got {other:?}"),
    }
}

#[test]
fn errors_never_carry_the_addon_address() {
    // A configured addon URL can hold credentials, so it must not reach an error
    // string that ends up in a log or a bug report.
    let secret = "https://movies.test.invalid/c/SECRET-TOKEN";
    let http = FixtureClient::new();
    let client = AddonClient::new(&http);
    let mut registry = AddonRegistry::new();

    let err = client.install(&mut registry, secret).unwrap_err();
    let rendered = err.to_string();

    assert!(
        !rendered.contains("SECRET-TOKEN"),
        "error leaked the address: {rendered}"
    );
}

#[test]
fn reads_a_series_with_seasons() {
    let http = FixtureClient::new()
        .with_json(format!("{SERIES_BASE}/manifest.json"), SERIES_MANIFEST)
        .with_json(
            format!("{SERIES_BASE}/meta/series/tt0903747.json"),
            SERIES_META,
        );
    let client = AddonClient::new(&http);
    let mut registry = AddonRegistry::new();
    let addon = client.install(&mut registry, SERIES_BASE).unwrap();

    let meta = client.meta(&addon, "series", "tt0903747").unwrap();

    assert_eq!(meta.seasons(), [1, 2]);
    assert_eq!(meta.season(1).len(), 2);
    assert_eq!(meta.season(1)[0].display_title(), "Pilot");
    // No title: fall back to SxxEyy rather than showing a raw id.
    assert_eq!(meta.season(1)[1].display_title(), "S01E02");
}

#[test]
fn the_detailed_resource_form_narrows_by_type() {
    let http =
        FixtureClient::new().with_json(format!("{SERIES_BASE}/manifest.json"), SERIES_MANIFEST);
    let client = AddonClient::new(&http);
    let mut registry = AddonRegistry::new();
    let addon = client.install(&mut registry, SERIES_BASE).unwrap();

    // Declared for `series` only.
    assert!(addon.manifest.resource_for("meta", "series").is_some());
    assert!(addon.manifest.resource_for("meta", "movie").is_none());
    let err = client.meta(&addon, "movie", "tt0111161").unwrap_err();
    assert!(matches!(err, Error::ResourceNotOffered { .. }));
}

#[test]
fn a_disabled_addon_is_left_out_of_lookups_but_stays_installed() {
    let http = movie_addon();
    let client = AddonClient::new(&http);
    let mut registry = AddonRegistry::new();
    client.install(&mut registry, MOVIE_BASE).unwrap();

    registry.set_enabled("org.eon.test.movies", false).unwrap();

    let found = client.streams_from_all(&registry, "movie", "tt0111161");
    assert_eq!(found.total(), 0);
    assert!(found.failures.is_empty());
    assert_eq!(registry.len(), 1, "disabling must not uninstall");
}

#[test]
fn catalogue_metadata_is_available_for_a_ui_without_extra_requests() {
    let http = movie_addon();
    let client = AddonClient::new(&http);
    let mut registry = AddonRegistry::new();
    let addon = client.install(&mut registry, MOVIE_BASE).unwrap();

    let top = &addon.manifest.catalogs[0];
    assert_eq!(top.display_name(), "Top Movies");
    assert!(top.is_searchable());
    assert!(top.required_extra().is_empty());

    // A catalogue with no name still has something to show.
    assert_eq!(addon.manifest.catalogs[1].display_name(), "featured");
    assert!(!addon.manifest.catalogs[1].is_searchable());
}
