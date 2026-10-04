// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 EON contributors
//
// Additional permission under GNU GPL version 3 section 7:
// see LICENSE-EXCEPTION.md (EON Module ABI Exception 1.0).

//! Settings.
//!
//! One typed document, persisted as JSON, with no key that sends anything
//! anywhere.
//!
//! ## There is no telemetry setting
//!
//! Not off by default — **absent** (madde 36). That distinction is the whole
//! point: a disabled switch is a switch, and a switch can be flipped by a
//! later release, a support article or an accident. There is nothing here to
//! flip. A test walks the serialised document and fails if a key matching
//! telemetry, analytics, tracking, metrics or reporting ever appears, so
//! adding one is a build failure rather than a code review someone has to
//! catch.
//!
//! ## Unknown keys are refused, not ignored
//!
//! The opposite choice from addon manifests, for the opposite reason. A
//! settings file is written by the user or by this application; a key nobody
//! recognises is a typo, and silently dropping a setting someone wrote is
//! worse than saying it is not a setting. The error names the key.
//!
//! ## Defaults are the cautious reading
//!
//! Update checks are **off** until asked for, because a check is a network
//! request that says something about this machine to a server (madde 39 and
//! the no-telemetry rule meet here). Torrent upload is **on**, because taking
//! without giving back breaks the swarm everyone else depends on, and a client
//! that leeches by default is a client that deserves the reputation.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{
    error::{Error, Result},
    ranking::RankingPreferences,
};

/// Settings schema version this build reads.
pub const SETTINGS_SCHEMA_VERSION: u32 = 0;

/// Playback behaviour.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct PlaybackSettings {
    /// Resume rather than restart when a watch position is at least this many
    /// seconds in.
    pub resume_after_seconds: f64,
    /// Treat an item as finished within this many seconds of the end, so
    /// credits do not leave everything "half watched".
    pub finished_within_seconds: f64,
    /// Subtitle languages to load automatically, most wanted first.
    pub subtitle_languages: Vec<String>,
    /// Start muted.
    pub start_muted: bool,
    /// Initial volume, 0-130 as mpv counts it.
    pub volume: u8,
    /// Extra arguments passed to the player process.
    ///
    /// The user's own machine and the user's own decision, so this exists. It
    /// is still validated: an argument that is not a `--flag` is refused,
    /// because this list becomes a process launch and a bare value there would
    /// be read by mpv as a file to play.
    pub player_arguments: Vec<String>,
}

impl Default for PlaybackSettings {
    fn default() -> Self {
        Self {
            resume_after_seconds: 30.0,
            finished_within_seconds: 90.0,
            subtitle_languages: Vec::new(),
            start_muted: false,
            volume: 100,
            player_arguments: Vec::new(),
        }
    }
}

/// Torrent streaming behaviour.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct TorrentSettings {
    /// Where pieces are written. `None` means a directory beside the
    /// executable, so the binary stays self-contained.
    pub download_directory: Option<String>,
    /// Most peers to connect to per torrent.
    pub peer_limit: u32,
    /// Download ceiling in kilobytes per second; `None` is unlimited.
    pub download_limit_kbps: Option<u32>,
    /// Upload ceiling in kilobytes per second; `None` is unlimited.
    pub upload_limit_kbps: Option<u32>,
    /// Keep seeding after playback ends.
    pub seed_after_playback: bool,
    /// Keep downloaded pieces on disk after the session ends.
    pub keep_files: bool,
    /// How many megabytes to pull ahead of the playhead before starting.
    pub prebuffer_megabytes: u32,
}

impl Default for TorrentSettings {
    fn default() -> Self {
        Self {
            download_directory: None,
            peer_limit: 100,
            download_limit_kbps: None,
            upload_limit_kbps: None,
            // On by default: a client that takes without giving back breaks
            // the swarm it depends on.
            seed_after_playback: true,
            keep_files: false,
            prebuffer_megabytes: 16,
        }
    }
}

/// Which release line to look at.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UpdateChannel {
    /// Published releases.
    Stable,
    /// Pre-releases, which is every build during the alpha line.
    Alpha,
}

impl UpdateChannel {
    /// The identifier as it appears in a release manifest.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Stable => "stable",
            Self::Alpha => "alpha",
        }
    }
}

/// Update behaviour.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct UpdateSettings {
    /// Look for a new release at startup.
    ///
    /// Off until asked for: a check is a network request that tells a server
    /// this machine exists and which version it runs.
    pub check_on_start: bool,
    /// Which line to look at.
    pub channel: UpdateChannel,
    /// Fetch the revocation list when checking for updates.
    ///
    /// On, and separate from `check_on_start`, because the two are not the
    /// same trade: declining update checks should not quietly also decline
    /// finding out that an installed module turned out to be malicious.
    pub refresh_revocations: bool,
}

impl Default for UpdateSettings {
    fn default() -> Self {
        Self {
            check_on_start: false,
            channel: UpdateChannel::Alpha,
            refresh_revocations: true,
        }
    }
}

/// Everything the user has chosen.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Settings {
    /// Schema version of this document.
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    /// Interface language as a BCP 47 tag. `tr` and `en` ship (madde 40).
    #[serde(default = "default_language")]
    pub language: String,
    /// Identifier of the installed theme module to use, or `None` for the
    /// built-in palette.
    #[serde(default)]
    pub theme: Option<String>,
    /// How to order sources.
    #[serde(default)]
    pub ranking: RankingPreferences,
    /// Playback behaviour.
    #[serde(default)]
    pub playback: PlaybackSettings,
    /// Torrent streaming behaviour.
    #[serde(default)]
    pub torrent: TorrentSettings,
    /// Update behaviour.
    #[serde(default)]
    pub updates: UpdateSettings,
}

fn default_schema_version() -> u32 {
    SETTINGS_SCHEMA_VERSION
}

fn default_language() -> String {
    "en".to_owned()
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            schema_version: SETTINGS_SCHEMA_VERSION,
            language: default_language(),
            theme: None,
            ranking: RankingPreferences::default(),
            playback: PlaybackSettings::default(),
            torrent: TorrentSettings::default(),
            updates: UpdateSettings::default(),
        }
    }
}

impl Settings {
    /// Read settings from stored JSON.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidSettings`] if the document is not readable, naming the
    /// problem — including an unrecognised key, which is reported rather than
    /// ignored so a typo does not look like a setting that had no effect.
    pub fn parse(text: &str) -> Result<Self> {
        let settings: Self =
            serde_json::from_str(text).map_err(|e| Error::InvalidSettings(e.to_string()))?;
        settings.validate()?;
        Ok(settings)
    }

    /// Serialise for storage.
    ///
    /// # Errors
    ///
    /// [`Error::Storage`] if serialisation fails.
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self).map_err(|e| Error::Storage {
            message: e.to_string(),
        })
    }

    /// Check the values the types cannot.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidSettings`] naming the setting and the acceptable range.
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != SETTINGS_SCHEMA_VERSION {
            return Err(Error::InvalidSettings(format!(
                "schemaVersion is {}, this build reads {SETTINGS_SCHEMA_VERSION}",
                self.schema_version
            )));
        }
        if !is_language_tag(&self.language) {
            return Err(Error::InvalidSettings(format!(
                "'{}' is not a language tag",
                self.language
            )));
        }
        if self.playback.volume > 130 {
            return Err(Error::InvalidSettings(format!(
                "playback.volume {} is above 130",
                self.playback.volume
            )));
        }
        if self.playback.resume_after_seconds < 0.0
            || !self.playback.resume_after_seconds.is_finite()
        {
            return Err(Error::InvalidSettings(
                "playback.resumeAfterSeconds must be a non-negative number".to_owned(),
            ));
        }
        if self.playback.finished_within_seconds < 0.0
            || !self.playback.finished_within_seconds.is_finite()
        {
            return Err(Error::InvalidSettings(
                "playback.finishedWithinSeconds must be a non-negative number".to_owned(),
            ));
        }
        for argument in &self.playback.player_arguments {
            validate_player_argument(argument)?;
        }
        if self.torrent.peer_limit == 0 || self.torrent.peer_limit > 1000 {
            return Err(Error::InvalidSettings(format!(
                "torrent.peerLimit {} is outside 1-1000",
                self.torrent.peer_limit
            )));
        }
        if self.torrent.prebuffer_megabytes > 512 {
            return Err(Error::InvalidSettings(format!(
                "torrent.prebufferMegabytes {} is above 512",
                self.torrent.prebuffer_megabytes
            )));
        }
        for (name, limit) in [
            (
                "torrent.downloadLimitKbps",
                self.torrent.download_limit_kbps,
            ),
            ("torrent.uploadLimitKbps", self.torrent.upload_limit_kbps),
        ] {
            if limit == Some(0) {
                return Err(Error::InvalidSettings(format!(
                    "{name} is 0, which would stall rather than mean unlimited; \
                     remove the setting for unlimited"
                )));
            }
        }
        Ok(())
    }

    /// Every setting as flat `path = value` lines, for a status display.
    #[must_use]
    pub fn summary(&self) -> BTreeMap<String, String> {
        let mut out = BTreeMap::new();
        out.insert("language".to_owned(), self.language.clone());
        out.insert(
            "theme".to_owned(),
            self.theme.clone().unwrap_or_else(|| "built-in".to_owned()),
        );
        out.insert(
            "ranking.minimumResolution".to_owned(),
            self.ranking
                .minimum_resolution
                .map_or_else(|| "none".to_owned(), |r| format!("{r:?}")),
        );
        out.insert(
            "ranking.audioLanguages".to_owned(),
            if self.ranking.preferred_audio_languages.is_empty() {
                "any".to_owned()
            } else {
                self.ranking.preferred_audio_languages.join(", ")
            },
        );
        out.insert(
            "playback.volume".to_owned(),
            self.playback.volume.to_string(),
        );
        out.insert(
            "playback.subtitleLanguages".to_owned(),
            if self.playback.subtitle_languages.is_empty() {
                "none".to_owned()
            } else {
                self.playback.subtitle_languages.join(", ")
            },
        );
        out.insert(
            "torrent.seedAfterPlayback".to_owned(),
            self.torrent.seed_after_playback.to_string(),
        );
        out.insert(
            "torrent.keepFiles".to_owned(),
            self.torrent.keep_files.to_string(),
        );
        out.insert(
            "torrent.prebufferMegabytes".to_owned(),
            self.torrent.prebuffer_megabytes.to_string(),
        );
        out.insert(
            "updates.checkOnStart".to_owned(),
            self.updates.check_on_start.to_string(),
        );
        out.insert(
            "updates.channel".to_owned(),
            self.updates.channel.as_str().to_owned(),
        );
        out.insert(
            "updates.refreshRevocations".to_owned(),
            self.updates.refresh_revocations.to_string(),
        );
        out
    }
}

/// A player argument is a flag, not a bare value.
///
/// This list becomes a process launch. A bare value in it would be read by mpv
/// as a file to play, which turns a settings typo into "the player opened
/// something nobody asked for".
fn validate_player_argument(argument: &str) -> Result<()> {
    if !argument.starts_with("--") {
        return Err(Error::InvalidSettings(format!(
            "playback.playerArguments entry '{argument}' must start with '--': a bare \
             value would be taken as a file to play"
        )));
    }
    if argument.contains('\0') {
        return Err(Error::InvalidSettings(format!(
            "playback.playerArguments entry '{argument}' contains a null byte"
        )));
    }
    Ok(())
}

fn is_language_tag(tag: &str) -> bool {
    let mut parts = tag.split('-');
    let Some(language) = parts.next() else {
        return false;
    };
    if !(2..=3).contains(&language.len()) || !language.chars().all(|c| c.is_ascii_lowercase()) {
        return false;
    }
    parts.all(|part| {
        (2..=8).contains(&part.len()) && part.chars().all(|c| c.is_ascii_alphanumeric())
    })
}

/// Key fragments that must never appear in the serialised settings document.
///
/// Exposed so a test in any crate can make the same assertion, and so the
/// list is a stated rule rather than a regex buried in one test.
pub const FORBIDDEN_KEY_FRAGMENTS: &[&str] = &[
    "telemetry",
    "analytics",
    "tracking",
    "metrics",
    "crashreport",
    "usagestats",
    "diagnostics",
    "beacon",
    "phonehome",
];

/// Whether `json` contains a key that would send something somewhere.
///
/// # Errors
///
/// [`Error::InvalidSettings`] if the text is not JSON.
pub fn find_forbidden_keys(json: &str) -> Result<Vec<String>> {
    let value: serde_json::Value =
        serde_json::from_str(json).map_err(|e| Error::InvalidSettings(e.to_string()))?;
    let mut found = Vec::new();
    collect_forbidden(&value, &mut found);
    found.sort_unstable();
    found.dedup();
    Ok(found)
}

fn collect_forbidden(value: &serde_json::Value, found: &mut Vec<String>) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, child) in map {
                let flattened: String = key
                    .chars()
                    .filter(|c| c.is_ascii_alphanumeric())
                    .map(|c| c.to_ascii_lowercase())
                    .collect();
                if FORBIDDEN_KEY_FRAGMENTS
                    .iter()
                    .any(|fragment| flattened.contains(fragment))
                {
                    found.push(key.clone());
                }
                collect_forbidden(child, found);
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                collect_forbidden(item, found);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::ranking::Resolution;

    #[test]
    fn there_is_no_telemetry_setting() {
        // Not off by default -- absent (madde 36). This test is the
        // enforcement: adding such a key becomes a build failure rather than
        // something a reviewer has to notice.
        let json = Settings::default().to_json().unwrap();
        let found = find_forbidden_keys(&json).unwrap();
        assert!(found.is_empty(), "settings grew a reporting key: {found:?}");
    }

    #[test]
    fn the_forbidden_key_check_actually_catches_something() {
        // A guard test that never fails is a guard test nobody should trust.
        let json = r#"{"updates":{"telemetryEnabled":false},"crash_reporting":true}"#;
        let found = find_forbidden_keys(json).unwrap();
        assert!(found.contains(&"telemetryEnabled".to_owned()), "{found:?}");
        assert!(found.contains(&"crash_reporting".to_owned()), "{found:?}");
    }

    #[test]
    fn defaults_are_the_cautious_reading() {
        let settings = Settings::default();
        // A check is a network request; it waits to be asked for.
        assert!(!settings.updates.check_on_start);
        // Learning that an installed module is malicious is a different trade.
        assert!(settings.updates.refresh_revocations);
        // Taking without giving back breaks the swarm.
        assert!(settings.torrent.seed_after_playback);
        // Nothing is kept on disk unless asked for.
        assert!(!settings.torrent.keep_files);
        assert_eq!(settings.language, "en");
    }

    #[test]
    fn an_unknown_key_is_reported_rather_than_dropped() {
        let json = r#"{"schemaVersion":0,"langauge":"tr"}"#;
        let err = Settings::parse(json).unwrap_err().to_string();
        // The typo is named, so the user can see why their setting did nothing.
        assert!(err.contains("langauge"), "{err}");
    }

    #[test]
    fn an_unknown_nested_key_is_reported_too() {
        let json = r#"{"schemaVersion":0,"torrent":{"peerLimitt":50}}"#;
        assert!(Settings::parse(json).is_err());
    }

    #[test]
    fn a_partial_document_fills_in_defaults() {
        let json = r#"{"language":"tr","torrent":{"keepFiles":true}}"#;
        let settings = Settings::parse(json).unwrap();
        assert_eq!(settings.language, "tr");
        assert!(settings.torrent.keep_files);
        // Untouched values are the defaults, not zeroes.
        assert_eq!(settings.torrent.peer_limit, 100);
        assert_eq!(settings.playback.volume, 100);
        assert!(settings.torrent.seed_after_playback);
    }

    #[test]
    fn a_bare_player_argument_is_refused() {
        // It would be read by mpv as a file to play.
        let mut settings = Settings::default();
        settings.playback.player_arguments = vec!["/etc/passwd".to_owned()];
        let err = settings.validate().unwrap_err().to_string();
        assert!(err.contains("must start with '--'"), "{err}");

        settings.playback.player_arguments =
            vec!["--no-border".to_owned(), "--volume-max=150".to_owned()];
        settings.validate().unwrap();
    }

    #[test]
    fn out_of_range_values_are_refused_by_name() {
        let mut settings = Settings::default();
        settings.playback.volume = 200;
        assert!(settings
            .validate()
            .unwrap_err()
            .to_string()
            .contains("volume"));

        let mut settings = Settings::default();
        settings.torrent.peer_limit = 0;
        assert!(settings
            .validate()
            .unwrap_err()
            .to_string()
            .contains("peerLimit"));

        let mut settings = Settings::default();
        settings.torrent.prebuffer_megabytes = 10_000;
        assert!(settings.validate().is_err());

        let settings = Settings {
            language: "Turkish!".to_owned(),
            ..Settings::default()
        };
        assert!(settings.validate().is_err());
    }

    #[test]
    fn a_zero_rate_limit_is_refused_rather_than_read_as_unlimited() {
        // Zero would stall rather than mean unlimited, and a user who typed it
        // meant one of the two.
        let mut settings = Settings::default();
        settings.torrent.download_limit_kbps = Some(0);
        let err = settings.validate().unwrap_err().to_string();
        assert!(err.contains("unlimited"), "{err}");
    }

    #[test]
    fn a_nonfinite_duration_is_refused() {
        let mut settings = Settings::default();
        settings.playback.resume_after_seconds = f64::NAN;
        assert!(settings.validate().is_err());
        settings.playback.resume_after_seconds = f64::INFINITY;
        assert!(settings.validate().is_err());
    }

    #[test]
    fn round_trips_through_json() {
        let mut settings = Settings {
            language: "tr-TR".to_owned(),
            theme: Some("community.example.theme".to_owned()),
            ..Settings::default()
        };
        settings.ranking.minimum_resolution = Some(Resolution::FullHd);
        settings.ranking.preferred_audio_languages = vec!["tr".to_owned(), "en".to_owned()];
        settings.playback.subtitle_languages = vec!["tr".to_owned()];
        settings.updates.channel = UpdateChannel::Stable;

        let json = settings.to_json().unwrap();
        assert_eq!(Settings::parse(&json).unwrap(), settings);
        // And still nothing that reports anywhere.
        assert!(find_forbidden_keys(&json).unwrap().is_empty());
    }

    #[test]
    fn an_unknown_schema_version_is_refused() {
        let json = r#"{"schemaVersion":99}"#;
        assert!(Settings::parse(json).is_err());
    }

    #[test]
    fn the_summary_covers_what_a_status_display_shows() {
        let summary = Settings::default().summary();
        for key in [
            "language",
            "theme",
            "playback.volume",
            "torrent.seedAfterPlayback",
            "updates.channel",
        ] {
            assert!(summary.contains_key(key), "{key} is missing");
        }
        assert_eq!(summary.get("theme").map(String::as_str), Some("built-in"));
    }
}
