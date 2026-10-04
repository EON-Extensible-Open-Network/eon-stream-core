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

### Added - the module manager and everything under it

This is v1 definition-of-done items 5 and 6, plus the half of item 1 that is not
packaging and the half of item 8 that is not an interface.

- `modules` - the module manager. Install, update, remove, enable, disable and
  order; dependency resolution with a topological load order and cycle
  detection; revocation applied to what is already installed. Installation is
  two steps on purpose: `prepare` runs every check and returns a
  `PreparedInstall`, `commit` takes that value. Nothing can be installed
  without one, and one cannot exist without having passed the checks, so "the
  permissions were shown before installing" is a shape the API has rather than
  a convention a caller is asked to remember (madde 3).
- `module` - module manifest types and validation, mirroring
  `schemas/module-manifest.v0.schema.json`. Strict where addon manifests are
  lenient, and for the opposite reason: an addon manifest comes from a stranger
  over HTTP and the goal is compatibility, while a module manifest describes
  something about to be installed on this machine.
- `signature` - Ed25519 verification against a trust set that holds several
  keys with validity windows, so rotation locks nobody out. **Verifies and never
  signs**: the signing half of the dependency is switched off, because a client
  that can also sign is a client whose compromise produces valid artefacts.
- `revocation` - version-scoped revocation with enumerated reasons, a
  last-known-good store that refuses an older list, and staleness reporting. A
  revoked module is disabled and reported with its reason and advisory, never
  quietly removed.
- `theme` - declarative theme documents resolved to flat tokens, with WCAG 2.1
  contrast ratios for every pair that actually gets rendered (madde 35). Both
  built-in palettes pass their own check, asserted by a test.
- `settings` - one typed document with **no reporting key anywhere in it**. A
  test walks the serialised form and fails if one appears (madde 36), and a
  second test proves that check is not vacuous.
- `update` - release manifest verification and the decision about whether to
  update, with downgrades refused (madde 39). Downloads nothing and installs
  nothing: this crate performs no I/O, and an updater that can write to disk is
  the most attractive thing in the application to compromise.
- `i18n` - Turkish and English catalogues in `i18n/`, loaded at compile time,
  with positional placeholders because word order is exactly what differs
  between these two languages. A missing translation falls back to English
  silently for the user and fails the build for us.
- `semver` - versions and **npm-syntax** ranges. Written here rather than taken
  from a crate because the contract asks for npm syntax and the `semver` crate
  parses Cargo syntax: they overlap enough to be dangerous, since a bare `1.2`
  means `^1.2` to Cargo and `=1.2.x` to npm.
- `time` - RFC 3339 parsing, using the standard days-from-civil algorithm. Key
  windows and revocation timestamps are security decisions; a timestamp read
  wrongly either expires a key early or honours a revoked one.
- `AddonClient::http` - exposes the configured transport, so a host does not
  build a second, differently configured client for the release manifest and
  the revocation list.
- 203 library tests and 18 compatibility tests, all offline.

### Decided
- **Canonical serialisation for signatures is JCS (RFC 8785)**, pinned here and
  in the spec. The subject is three string members, so the canonical form is
  one line any implementation can produce by concatenation. It was pinned
  before any key exists because the spec's own warning was right: two
  implementations disagreeing on byte order produce signatures that verify in
  one client and fail in another.
- **v1 installs declarative modules only.** `wasm` is named in the contract and
  refused by name, which is different from being unrecognised: there is no
  sandbox yet, and a security claim without one would not be honest (madde 4).

### Added dependencies
Each is a supply-chain commitment (madde 37) and is justified where it is
declared: `ed25519-dalek` (the one algorithm the contract defines, pure Rust,
with signing and key generation switched off), `sha2`, and `base64`. No date
library and no regex engine: both would have been for one function each.

### Still open
- Module sandbox: wasmtime versus isolated webview (madde 4). Does not block v1.
- **No key in the hierarchy exists**, so every build ships an empty trust set
  and installs nothing. Custody belongs to a legal entity that does not exist
  yet (madde 30); minting a root key for one person to hold in the meantime
  would be worse than having none. A client reads `eon-trust.json` beside the
  executable, which is how the chain is exercised today and how an institution
  will enrol its own key.

[Unreleased]: https://github.com/EON-Extensible-Open-Network/eon-stream-core/compare/main...HEAD
