# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Semantic versioning
begins at 0.1.0; nothing is released yet.

## [Unreleased]

### Added — the addon protocol client

Adding an addon and browsing it now works end to end.

- `address` — turns what a person pasted into request URLs. Accepts
  `https://host/manifest.json`, a bare host, a trailing slash, and `stremio://`
  links; rejects plain HTTP anywhere but loopback; keeps a configuration path
  intact.
- `manifest` — Stremio-compatible manifest types plus the reserved `eon`
  extension key. Validation refuses an addon-API major version this build does
  not implement, and says so rather than failing obscurely later (madde 5).
- `types` — catalogue entries, metadata with seasons and episodes, streams,
  subtitles. `Stream::source` classifies a source as direct, torrent, YouTube or
  external, and returns `None` for a stream object with nothing playable in it,
  which addons do send.
- `registry` — the installed addon list in user order: add, remove, enable,
  reorder, persist. Identity is the manifest id, not the address.
- `client` — `catalog`, `meta`, `stream`, `subtitles` for one addon, and
  `streams_from_all` / `subtitles_from_all` across every installed addon with
  per-addon failure isolation (madde 1).
- `http` — the transport boundary. This crate performs no I/O; the host supplies
  an `HttpClient`. `FixtureClient` answers from recorded responses, which is what
  lets the compatibility suite avoid depending on third-party uptime (madde 1).
- `serde_lax` — collection fields accept an explicit `null` as empty. Required,
  not cosmetic: see below.
- `examples/browse.rs` — a terminal front end. Not the product, but it exercises
  the protocol against real addons today instead of waiting for a window.
- 33 tests, all offline, over pinned fixtures in `tests/fixtures/`.

### Decided
- **madde 1: the protocol layer is ours.** `stremio-core` is not a dependency.
  Verified against Cinemeta (manifest, 8 catalogues, search, movie and series
  metadata) and OpenSubtitles v3 (38 subtitle tracks). The protocol is four
  endpoints and plain JSON; `stremio-core` would also bring Stremio's state
  model, library sync and account client, and with them Stremio's product
  decisions. It stays a behaviour reference, not a dependency.

### Fixed — found by running against real addons
- **Explicit `null` where an array belongs.** Cinemeta sends `"videos": null` on
  some items. `#[serde(default)]` only covers an *absent* field, so a strict
  reader refuses the most widely used addon there is. Every collection field now
  accepts absent, `null`, or a value; a value of the wrong type is still an
  error.
- **An addon's credentials live in its URL path.** "Do not log the URL" was not
  enough — logging the *path* leaks the same secret. A test
  (`errors_never_carry_the_addon_address`) caught the fixture client echoing it.
  No error message carries either now.

### Changed
- Pinned toolchain moved from 1.83.0 to 1.98.1. 1.83 is from November 2024 and
  current dependency trees require edition 2024.
- CI no longer sets `RUSTFLAGS: -D warnings`. `Cargo.toml` denies
  `clippy::all`, `unwrap_used` and `panic` — the lints that matter.
  `clippy::pedantic` warns on top of that and carries style opinions that make a
  poor gate: a build should not break over a missing pair of backticks.

### Still open
- Module sandbox: wasmtime versus isolated webview (madde 4). Does not block v1.
- Module management, signature verification and revocation, settings, updater.

[Unreleased]: https://github.com/EON-Extensible-Open-Network/eon-stream-core/compare/main...HEAD
