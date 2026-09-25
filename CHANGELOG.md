# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Semantic versioning
begins at 0.1.0; nothing is released yet.

## [Unreleased]

### Added
- Crate skeleton with the intended module layout: `manifest`, `modules`, `addons`,
  `signing`, `settings`, `updater`, `error`.
- Lint policy: `unsafe_code` forbidden; `unwrap_used` and `panic` denied - a panic in the
  module manager takes the whole application down with it.
- `deny.toml` licence and advisory gate; permissive inbound licences only.
- CI: fmt, clippy, test on Linux and Windows; cargo-deny; REUSE; DCO check.

### Open decisions blocking implementation
- Protocol layer: `stremio-core` as a dependency vs. implementing the protocol directly
  (madde 1).
- Sandbox for code-executing modules: wasmtime vs. isolated webview (madde 4). Does not
  block v1, which ships declarative modules only.

[Unreleased]: https://github.com/EON-Extensible-Open-Network/eon-stream-core/compare/main...HEAD
