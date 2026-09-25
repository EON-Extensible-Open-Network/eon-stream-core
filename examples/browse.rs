// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 EON contributors

//! Add an addon and look through it, from a terminal.
//!
//! This is not the product — the product is a Tauri application
//! (`eon-stream-app`). It exists so the protocol layer can be exercised against
//! real addons today, without waiting for a window to draw. It is also the
//! experiment that answers madde 1: if real addons resolve end to end through
//! code we wrote ourselves, `stremio-core` is not needed as a dependency.
//!
//! ```text
//! cargo run --example browse -- add   https://addon.example.org/manifest.json
//! cargo run --example browse -- list
//! cargo run --example browse -- catalogs
//! cargo run --example browse -- catalog <addon-id> <type> <catalog-id> [search terms]
//! cargo run --example browse -- meta    <addon-id> <type> <id>
//! cargo run --example browse -- streams <type> <id>
//! cargo run --example browse -- subtitles <type> <id>
//! cargo run --example browse -- remove  <addon-id>
//! ```
//!
//! The addon list is stored next to the binary in `eon-addons.json`. That is a
//! convenience for this example, not where the application will keep it.

#![allow(clippy::unwrap_used, clippy::print_stdout, clippy::print_stderr)]

use std::{fs, io::Read, path::PathBuf, process::ExitCode, time::Duration};

use eon_stream_core::{
    http::{HttpClient, HttpError, HttpResponse, Limits},
    AddonClient, AddonRegistry, StreamSource,
};

/// A real HTTP client, kept out of the library so it pulls in no network stack.
struct UreqClient {
    agent: ureq::Agent,
    limits: Limits,
}

impl UreqClient {
    fn new() -> Self {
        let limits = Limits::default();
        let agent = ureq::AgentBuilder::new()
            .timeout(Duration::from_millis(limits.timeout_ms))
            .redirects(u32::from(limits.max_redirects))
            .user_agent("EON-Stream/0.0 (+https://github.com/EON-Extensible-Open-Network)")
            .build();
        Self { agent, limits }
    }
}

impl HttpClient for UreqClient {
    fn get(&self, url: &str) -> Result<HttpResponse, HttpError> {
        let response = match self.agent.get(url).call() {
            Ok(response) => response,
            // A non-success status is a response, not a transport failure: the
            // caller needs the status the addon actually sent.
            Err(ureq::Error::Status(status, response)) => {
                let mut body = Vec::new();
                let _ = response.into_reader().read_to_end(&mut body);
                return Ok(HttpResponse { status, body });
            }
            // The message must never contain the URL: an addon's configuration
            // credentials live in its path.
            Err(ureq::Error::Transport(transport)) => {
                return Err(HttpError::new(
                    transport
                        .message()
                        .map_or_else(|| transport.kind().to_string(), ToOwned::to_owned),
                ));
            }
        };

        let status = response.status();
        let mut body = Vec::new();
        // Read at most one byte past the cap, so the size check can fail rather
        // than the allocator.
        let cap = self.limits.max_body_bytes as u64 + 1;
        response
            .into_reader()
            .take(cap)
            .read_to_end(&mut body)
            .map_err(|e| HttpError::new(e.to_string()))?;

        Ok(HttpResponse { status, body })
    }

    fn limits(&self) -> Limits {
        self.limits
    }
}

fn store_path() -> PathBuf {
    PathBuf::from("eon-addons.json")
}

fn load() -> AddonRegistry {
    fs::read_to_string(store_path())
        .ok()
        .and_then(|json| AddonRegistry::from_json(&json).ok())
        .unwrap_or_default()
}

fn save(registry: &AddonRegistry) {
    match registry.to_json() {
        Ok(json) => {
            if let Err(e) = fs::write(store_path(), json) {
                eprintln!("could not write the addon list: {e}");
            }
        }
        Err(e) => eprintln!("could not serialise the addon list: {e}"),
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let http = UreqClient::new();
    let client = AddonClient::new(&http);
    let mut registry = load();

    let command = args.first().map(String::as_str).unwrap_or("help");

    match command {
        "add" => {
            let Some(address) = args.get(1) else {
                eprintln!("usage: add <addon url>");
                return ExitCode::FAILURE;
            };
            match client.install(&mut registry, address) {
                Ok(addon) => {
                    save(&registry);
                    let s = addon.summary();
                    println!("added {} {} ({})", s.name, s.version, s.id);
                    println!("  types      {}", s.types.join(", "));
                    println!("  resources  {}", s.resources.join(", "));
                    println!("  catalogues {}", s.catalog_count);
                    if s.configuration_required {
                        println!("  note: this addon says it needs configuring first");
                    }
                }
                Err(e) => {
                    eprintln!("could not add the addon: {e}");
                    return ExitCode::FAILURE;
                }
            }
        }

        "list" => {
            if registry.is_empty() {
                println!("no addons installed");
                println!("EON Stream ships with none, ever -- add one with:");
                println!("  cargo run --example browse -- add <url>");
            }
            for (index, s) in registry.summaries().iter().enumerate() {
                let state = if s.enabled { "" } else { "  [disabled]" };
                println!(
                    "{}. {} {} ({}){}",
                    index + 1,
                    s.name,
                    s.version,
                    s.id,
                    state
                );
                if let Some(description) = &s.description {
                    println!("   {description}");
                }
            }
        }

        "catalogs" => {
            for addon in registry.addons() {
                println!("{} ({})", addon.manifest.name, addon.id());
                if addon.manifest.catalogs.is_empty() {
                    println!("   no browsable catalogues");
                }
                for catalog in &addon.manifest.catalogs {
                    let searchable = if catalog.is_searchable() {
                        "  searchable"
                    } else {
                        ""
                    };
                    println!(
                        "   {} / {}  \"{}\"{}",
                        catalog.content_type,
                        catalog.id,
                        catalog.display_name(),
                        searchable
                    );
                    let required = catalog.required_extra();
                    if !required.is_empty() {
                        println!("      requires: {}", required.join(", "));
                    }
                }
            }
        }

        "catalog" => {
            let (Some(id), Some(content_type), Some(catalog_id)) =
                (args.get(1), args.get(2), args.get(3))
            else {
                eprintln!("usage: catalog <addon-id> <type> <catalog-id> [search terms]");
                return ExitCode::FAILURE;
            };
            let Some(addon) = registry.get(id) else {
                eprintln!("no installed addon with id '{id}'");
                return ExitCode::FAILURE;
            };
            let search = args[4..].join(" ");
            let extra: Vec<(&str, &str)> = if search.is_empty() {
                Vec::new()
            } else {
                vec![("search", search.as_str())]
            };

            match client.catalog(addon, content_type, catalog_id, &extra) {
                Ok(page) => {
                    println!("{} item(s)", page.len());
                    for item in page {
                        let year = item.release_info.as_deref().unwrap_or("----");
                        let rating = item
                            .imdb_rating
                            .as_deref()
                            .map(|r| format!("  {r}"))
                            .unwrap_or_default();
                        println!("  {}  {}  {}{}", item.id, year, item.display_name(), rating);
                    }
                }
                Err(e) => {
                    eprintln!("catalogue request failed: {e}");
                    return ExitCode::FAILURE;
                }
            }
        }

        "meta" => {
            let (Some(id), Some(content_type), Some(item_id)) =
                (args.get(1), args.get(2), args.get(3))
            else {
                eprintln!("usage: meta <addon-id> <type> <id>");
                return ExitCode::FAILURE;
            };
            let Some(addon) = registry.get(id) else {
                eprintln!("no installed addon with id '{id}'");
                return ExitCode::FAILURE;
            };
            match client.meta(addon, content_type, item_id) {
                Ok(meta) => {
                    println!("{}", meta.display_name());
                    if let Some(year) = &meta.release_info {
                        println!("  year     {year}");
                    }
                    if let Some(runtime) = &meta.runtime {
                        println!("  runtime  {runtime}");
                    }
                    if !meta.genres.is_empty() {
                        println!("  genres   {}", meta.genres.join(", "));
                    }
                    if let Some(description) = &meta.description {
                        println!("\n{description}");
                    }
                    for season in meta.seasons() {
                        println!("\nSeason {season}");
                        for video in meta.season(season) {
                            println!("  {}  {}", video.id, video.display_title());
                        }
                    }
                }
                Err(e) => {
                    eprintln!("metadata request failed: {e}");
                    return ExitCode::FAILURE;
                }
            }
        }

        "streams" => {
            let (Some(content_type), Some(item_id)) = (args.get(1), args.get(2)) else {
                eprintln!("usage: streams <type> <id>");
                return ExitCode::FAILURE;
            };
            let found = client.streams_from_all(&registry, content_type, item_id);

            for (addon_id, streams) in &found.items {
                let name = registry
                    .get(addon_id)
                    .map_or(addon_id.as_str(), |a| a.manifest.name.as_str());
                println!("{name}");
                for stream in streams {
                    let kind = match stream.source() {
                        Some(StreamSource::Direct(_)) => "http",
                        Some(StreamSource::Torrent { .. }) => "torrent",
                        Some(StreamSource::YouTube(_)) => "youtube",
                        Some(StreamSource::External(_)) => "external",
                        None => "unplayable",
                    };
                    println!("  [{kind:>10}] {}", stream.display_label());
                }
            }

            // Both halves get reported: showing only results would hide that
            // half the user's addons are broken.
            for failure in &found.failures {
                eprintln!("failed: {failure}");
            }
            println!(
                "\n{} source(s) from {} addon(s); {} addon(s) failed",
                found.total(),
                found.items.len(),
                found.failures.len()
            );
        }

        "subtitles" => {
            let (Some(content_type), Some(item_id)) = (args.get(1), args.get(2)) else {
                eprintln!("usage: subtitles <type> <id>");
                return ExitCode::FAILURE;
            };
            let found = client.subtitles_from_all(&registry, content_type, item_id);
            for (addon_id, tracks) in &found.items {
                let name = registry
                    .get(addon_id)
                    .map_or(addon_id.as_str(), |a| a.manifest.name.as_str());
                println!("{name}: {} track(s)", tracks.len());
                for track in tracks.iter().take(10) {
                    println!("  {}  {}", track.lang.as_deref().unwrap_or("??"), track.id);
                }
            }
            for failure in &found.failures {
                eprintln!("failed: {failure}");
            }
            println!(
                "\n{} track(s) from {} addon(s); {} addon(s) failed",
                found.total(),
                found.items.len(),
                found.failures.len()
            );
        }

        "remove" => {
            let Some(id) = args.get(1) else {
                eprintln!("usage: remove <addon-id>");
                return ExitCode::FAILURE;
            };
            match registry.remove(id) {
                Ok(addon) => {
                    save(&registry);
                    println!("removed {}", addon.manifest.name);
                }
                Err(e) => {
                    eprintln!("{e}");
                    return ExitCode::FAILURE;
                }
            }
        }

        _ => {
            println!("EON Stream -- addon protocol example");
            println!();
            println!("  add      <url>                              install an addon");
            println!("  list                                        installed addons");
            println!("  catalogs                                    catalogues on offer");
            println!("  catalog  <addon-id> <type> <cat-id> [query]  browse a catalogue");
            println!("  meta     <addon-id> <type> <id>             item details");
            println!("  streams  <type> <id>                        sources from every addon");
            println!(
                "  subtitles <type> <id>                       subtitle tracks from every addon"
            );
            println!("  remove   <addon-id>                         uninstall");
        }
    }

    ExitCode::SUCCESS
}
