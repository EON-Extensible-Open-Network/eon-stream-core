# eon-stream-core

The core library: **module manager, addon protocol client, manifest and signature
verification, settings, updater logic.** Everything else in EON Stream is a module on top of
this.

[![Status](https://img.shields.io/badge/status-Faz%200%20·%20active-f59e0b)](https://github.com/EON-Extensible-Open-Network/eon-docs/blob/main/plan/eon-plan.md)
[![License](https://img.shields.io/badge/license-GPL--3.0--or--later%20+%20module%20exception-3b82f6)](LICENSE)

---

## What this crate is

A library, not an application. It has no user interface, no window, and no player: it is
the part of EON Stream that decides *what* to do, while `eon-stream-engine` moves bytes and
`eon-stream-app` draws pixels.

Responsibilities:

- **Module manager** — install, update, remove, resolve dependencies, verify signatures,
  enforce declared permissions. The core is *only* a module manager, settings, and an
  updater (madde 3).
- **Addon protocol client** — resolve `catalog` / `meta` / `stream` / `subtitles` against
  remote addons, merge results, isolate failures per addon.
- **Manifest validation** — against the schemas in
  [`eon-stream-spec`](https://github.com/EON-Extensible-Open-Network/eon-stream-spec).
- **Signature and revocation** — verify Ed25519 envelopes, apply the revocation list, refuse
  revoked or downgraded versions.
- **Compatibility suite** — the pinned addon fixtures live in `tests/fixtures/`.

Explicitly **not** here: the user interface, the BitTorrent engine, mpv, any Tauri
dependency. A dependency on a GUI toolkit in this crate is a design failure.

## Architecture rule that constrains this crate

> First-party modules use the same API as community modules (madde 3).

This is enforced, not trusted: CI fails if a first-party module reaches a capability the
published Module ABI does not offer. Without the check, the rule quietly erodes the first
time something is urgent — and then the extension point is a second-class citizen forever.

## Status

**Faz 0, and the responsibilities above are now implemented.** 203 library tests and 18
compatibility tests, all offline.

Both decisions that shaped this crate are settled:

1. **Protocol layer (madde 1): ours.** `stremio-core` is not a dependency. Verified against
   Cinemeta and OpenSubtitles v3; the protocol turned out to be four endpoints and plain
   JSON, while `stremio-core` would also have brought Stremio's state model, library sync
   and account client, and with them Stremio's product decisions.
2. **Sandbox for code-executing modules (madde 4): still open**, and it does not block v1.
   wasmtime with capability-based host functions, against an isolated webview with an IPC
   allowlist. Until one exists, `modules` refuses a `wasm` module **by name** rather than
   pretending not to recognise it — the contract defines the runtime, and this build does
   not execute it.

### What this means in practice today

**No key in the signing hierarchy exists**, so every build ships with an empty trust set
and installs nothing. That is designed behaviour, not a defect: custody belongs to a legal
entity that does not exist yet (madde 30), and minting a root key for one person to hold on
a laptop would produce signatures that look like the real thing.

The mechanism is complete and exercised rather than theoretical. A client reads its trust
set from `eon-trust.json` beside the executable, so anyone can mint a key, sign a module and
watch the whole chain run — signature verified against a rotating trust set, content hash
recomputed here and never taken from the caller, permissions shown before installing,
tampered content refused, downgrade refused, revocation applied. That file is a statement of
what one machine trusts, which is also how an institution will enrol its own key. There is
no flag that skips verification.

### Two invariants worth stating out loud

**This crate verifies and never signs.** The signing half of `ed25519-dalek` is switched
off, because a client that can also sign is a client whose compromise produces valid
artefacts.

**There is no telemetry setting.** Not off by default — absent (madde 36). A test walks the
serialised settings document and fails if a key matching telemetry, analytics, tracking,
metrics or reporting ever appears, and a second test proves that check is not vacuous. Both
run as named checks in CI.

## Build

```bash
rustup show                 # toolchain is pinned in rust-toolchain.toml
cargo test
cargo clippy -- -D warnings
cargo fmt --check
cargo deny check            # licenses + advisories
```

No system dependencies. If building this crate ever needs mpv or a torrent engine
installed, a layer has leaked.

## License

`GPL-3.0-or-later` **WITH** the EON Module ABI Exception 1.0 — see [`LICENSE`](LICENSE)
and [`LICENSE-EXCEPTION.md`](LICENSE-EXCEPTION.md).

Plainly: the core stays open and cannot be taken into a closed product. Third-party modules
that talk to it only across the published Module ABI may be licensed however their authors
wish — including closed, which is what makes an institutional integration such as a closed
e-Okul connector possible (madde 20).

The exception exists from the first commit because contributions are taken under the DCO:
adding it later would require every contributor's agreement, which in practice means never.

Third-party attributions: [`NOTICE`](NOTICE).

## Related

[eon-stream-spec](https://github.com/EON-Extensible-Open-Network/eon-stream-spec) — the contracts this implements ·
[eon-stream-engine](https://github.com/EON-Extensible-Open-Network/eon-stream-engine) — streaming and playback ·
[eon-stream-app](https://github.com/EON-Extensible-Open-Network/eon-stream-app) — the desktop client ·
[eon-docs](https://github.com/EON-Extensible-Open-Network/eon-docs) — the plan

## Contributing

[CONTRIBUTING.md](https://github.com/EON-Extensible-Open-Network/.github/blob/main/CONTRIBUTING.md). Sign off your
commits (`git commit -s`). By contributing here you grant the module exception as well — see
`LICENSE-EXCEPTION.md`.
