// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 EON contributors
//
// Additional permission under GNU GPL version 3 section 7:
// see LICENSE-EXCEPTION.md (EON Module ABI Exception 1.0).

//! Where you got to, and what to play next.
//!
//! Everything here stays **on the device**. No account, no sync, nothing sent
//! anywhere (madde 7, 31, 36). That is not a limitation to be lifted later: a
//! viewer that reports what you watched is the thing this project promised not
//! to be.
//!
//! Two decisions worth naming:
//!
//! * A position near the end counts as **finished**, not as "resume at 99%".
//!   Resuming into the credits is worse than starting over.
//! * The binge group of the source that was used is remembered, so the next
//!   episode can keep the same release instead of asking again.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{Error, Result};

/// Fraction of the runtime past which an item counts as watched.
const FINISHED_FRACTION: f64 = 0.92;

/// Seconds from the start below which there is nothing worth resuming.
const RESUME_FLOOR_SECS: f64 = 30.0;

/// One thing that was watched.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchEntry {
    /// Content type, for example `movie` or `series`.
    pub content_type: String,
    /// Item identifier, as the addon gave it. For an episode this is the episode
    /// id, so each episode resumes on its own.
    pub id: String,
    /// What to show in a list.
    pub name: String,
    /// For an episode, the series it belongs to, so "continue watching" can show
    /// one line per series rather than one per episode.
    #[serde(default)]
    pub series_id: Option<String>,
    /// Season number, for an episode.
    #[serde(default)]
    pub season: Option<u32>,
    /// Episode number within the season.
    #[serde(default)]
    pub episode: Option<u32>,
    /// Where playback got to, in seconds.
    pub position_secs: f64,
    /// Total runtime in seconds, when it was known.
    #[serde(default)]
    pub duration_secs: Option<f64>,
    /// Binge group of the source that was used, for keeping the same release.
    #[serde(default)]
    pub binge_group: Option<String>,
    /// Addon that provided the source.
    #[serde(default)]
    pub addon_id: Option<String>,
    /// When this was last touched, as a Unix timestamp in seconds.
    pub updated_at: u64,
}

impl WatchEntry {
    /// How far through, when the runtime is known.
    #[must_use]
    pub fn progress(&self) -> Option<f64> {
        let duration = self.duration_secs?;
        if duration <= 0.0 {
            return None;
        }
        Some((self.position_secs / duration).clamp(0.0, 1.0))
    }

    /// Whether this counts as watched to the end.
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.progress().is_some_and(|p| p >= FINISHED_FRACTION)
    }

    /// Where to start from, or `None` when starting over is the right answer.
    #[must_use]
    pub fn resume_position(&self) -> Option<f64> {
        if self.is_finished() || self.position_secs < RESUME_FLOOR_SECS {
            return None;
        }
        Some(self.position_secs)
    }

    /// A line for a list.
    #[must_use]
    pub fn display_line(&self) -> String {
        let where_at = match (self.progress(), self.resume_position()) {
            (Some(fraction), Some(position)) => {
                format!("{:.0}% · resume at {}", fraction * 100.0, clock(position))
            }
            (Some(fraction), None) if self.is_finished() => {
                format!("{:.0}% · finished", fraction * 100.0)
            }
            _ => format!("at {}", clock(self.position_secs)),
        };
        match (self.season, self.episode) {
            (Some(s), Some(e)) => format!("{} S{s:02}E{e:02} — {where_at}", self.name),
            _ => format!("{} — {where_at}", self.name),
        }
    }
}

/// Seconds as `h:mm:ss` or `m:ss`.
#[must_use]
pub fn clock(seconds: f64) -> String {
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let total = seconds.max(0.0) as u64;
    let (hours, minutes, secs) = (total / 3600, (total % 3600) / 60, total % 60);
    if hours > 0 {
        format!("{hours}:{minutes:02}:{secs:02}")
    } else {
        format!("{minutes}:{secs:02}")
    }
}

/// Everything watched, keyed by content type and id.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WatchHistory {
    entries: BTreeMap<String, WatchEntry>,
}

impl WatchHistory {
    /// An empty history.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Restore from stored JSON.
    ///
    /// # Errors
    ///
    /// [`Error::Storage`] when the stored history cannot be read.
    pub fn from_json(json: &str) -> Result<Self> {
        serde_json::from_str(json).map_err(|e| Error::Storage {
            message: e.to_string(),
        })
    }

    /// Serialise for storage.
    ///
    /// # Errors
    ///
    /// [`Error::Storage`] when serialisation fails.
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self).map_err(|e| Error::Storage {
            message: e.to_string(),
        })
    }

    fn key(content_type: &str, id: &str) -> String {
        format!("{content_type}:{id}")
    }

    /// Record or update where playback got to.
    ///
    /// Only the fields that were supplied are overwritten, so a later update
    /// that does not know the duration cannot erase one that did.
    pub fn record(&mut self, entry: WatchEntry) {
        let key = Self::key(&entry.content_type, &entry.id);
        match self.entries.get_mut(&key) {
            Some(existing) => {
                existing.position_secs = entry.position_secs;
                existing.updated_at = entry.updated_at;
                if entry.duration_secs.is_some() {
                    existing.duration_secs = entry.duration_secs;
                }
                if entry.binge_group.is_some() {
                    existing.binge_group = entry.binge_group;
                }
                if entry.addon_id.is_some() {
                    existing.addon_id = entry.addon_id;
                }
                if !entry.name.is_empty() {
                    existing.name = entry.name;
                }
            }
            None => {
                self.entries.insert(key, entry);
            }
        }
    }

    /// What is known about one item.
    #[must_use]
    pub fn get(&self, content_type: &str, id: &str) -> Option<&WatchEntry> {
        self.entries.get(&Self::key(content_type, id))
    }

    /// Where to resume one item, if anywhere.
    #[must_use]
    pub fn resume_position(&self, content_type: &str, id: &str) -> Option<f64> {
        self.get(content_type, id)?.resume_position()
    }

    /// The binge group last used for a series, so the next episode can keep the
    /// same release.
    #[must_use]
    pub fn binge_group_for_series(&self, series_id: &str) -> Option<&str> {
        self.entries
            .values()
            .filter(|e| e.series_id.as_deref() == Some(series_id))
            .max_by_key(|e| e.updated_at)?
            .binge_group
            .as_deref()
    }

    /// Unfinished items, most recent first, one line per series.
    ///
    /// An episode stands in for its series: five half-watched episodes of one
    /// show is one thing to continue, not five.
    #[must_use]
    pub fn continue_watching(&self, limit: usize) -> Vec<&WatchEntry> {
        let mut candidates: Vec<&WatchEntry> = self
            .entries
            .values()
            .filter(|e| !e.is_finished() && e.resume_position().is_some())
            .collect();
        candidates.sort_by_key(|entry| std::cmp::Reverse(entry.updated_at));

        let mut seen_series = std::collections::HashSet::new();
        let mut result = Vec::new();
        for entry in candidates {
            if let Some(series) = &entry.series_id {
                if !seen_series.insert(series.clone()) {
                    continue;
                }
            }
            result.push(entry);
            if result.len() >= limit {
                break;
            }
        }
        result
    }

    /// Forget one item.
    pub fn forget(&mut self, content_type: &str, id: &str) -> bool {
        self.entries.remove(&Self::key(content_type, id)).is_some()
    }

    /// Forget everything.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// How many items are recorded.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether nothing is recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Seconds since the Unix epoch, or zero if the clock is unreadable.
#[must_use]
pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn entry(id: &str, position: f64, duration: Option<f64>, updated: u64) -> WatchEntry {
        WatchEntry {
            content_type: "movie".into(),
            id: id.into(),
            name: format!("Film {id}"),
            series_id: None,
            season: None,
            episode: None,
            position_secs: position,
            duration_secs: duration,
            binge_group: None,
            addon_id: None,
            updated_at: updated,
        }
    }

    #[test]
    fn near_the_end_counts_as_finished_not_as_resume() {
        let watched = entry("a", 5_900.0, Some(6_000.0), 1);
        assert!(watched.is_finished());
        assert_eq!(watched.resume_position(), None);
    }

    #[test]
    fn the_first_few_seconds_are_not_worth_resuming() {
        let barely = entry("a", 12.0, Some(6_000.0), 1);
        assert_eq!(barely.resume_position(), None);
    }

    #[test]
    fn the_middle_resumes() {
        let halfway = entry("a", 3_000.0, Some(6_000.0), 1);
        assert_eq!(halfway.resume_position(), Some(3_000.0));
        assert!((halfway.progress().unwrap() - 0.5).abs() < 0.01);
    }

    #[test]
    fn an_update_without_a_duration_does_not_erase_one() {
        let mut history = WatchHistory::new();
        history.record(entry("a", 100.0, Some(6_000.0), 1));
        history.record(entry("a", 200.0, None, 2));
        let stored = history.get("movie", "a").unwrap();
        assert_eq!(stored.position_secs, 200.0);
        assert_eq!(stored.duration_secs, Some(6_000.0));
    }

    #[test]
    fn continue_watching_shows_one_line_per_series() {
        let mut history = WatchHistory::new();
        for episode in 1..=3 {
            history.record(WatchEntry {
                content_type: "series".into(),
                id: format!("tt1:1:{episode}"),
                name: "A Show".into(),
                series_id: Some("tt1".into()),
                season: Some(1),
                episode: Some(episode),
                position_secs: 600.0,
                duration_secs: Some(2_400.0),
                binge_group: Some("group-a".into()),
                addon_id: Some("addon".into()),
                updated_at: u64::from(episode),
            });
        }
        history.record(entry("film", 1_000.0, Some(6_000.0), 99));

        let list = history.continue_watching(10);
        assert_eq!(list.len(), 2, "expected one series line plus the film");
        // Most recent first: the film was touched last.
        assert_eq!(list[0].id, "film");
        // And the series line is the latest episode watched.
        assert_eq!(list[1].episode, Some(3));
    }

    #[test]
    fn finished_items_are_not_offered_to_continue() {
        let mut history = WatchHistory::new();
        history.record(entry("done", 5_900.0, Some(6_000.0), 1));
        assert!(history.continue_watching(10).is_empty());
    }

    #[test]
    fn the_last_used_release_is_remembered_per_series() {
        let mut history = WatchHistory::new();
        for (episode, group, when) in [(1, "old-group", 1), (2, "new-group", 2)] {
            history.record(WatchEntry {
                content_type: "series".into(),
                id: format!("tt1:1:{episode}"),
                name: "A Show".into(),
                series_id: Some("tt1".into()),
                season: Some(1),
                episode: Some(episode),
                position_secs: 100.0,
                duration_secs: Some(2_400.0),
                binge_group: Some(group.to_owned()),
                addon_id: None,
                updated_at: when,
            });
        }
        assert_eq!(history.binge_group_for_series("tt1"), Some("new-group"));
    }

    #[test]
    fn survives_a_round_trip_through_storage() {
        let mut history = WatchHistory::new();
        history.record(entry("a", 1_234.0, Some(6_000.0), 7));
        let restored = WatchHistory::from_json(&history.to_json().unwrap()).unwrap();
        assert_eq!(restored.len(), 1);
        assert_eq!(restored.resume_position("movie", "a"), Some(1_234.0));
    }

    #[test]
    fn times_read_like_times() {
        assert_eq!(clock(0.0), "0:00");
        assert_eq!(clock(95.0), "1:35");
        assert_eq!(clock(3_725.0), "1:02:05");
        assert_eq!(clock(-5.0), "0:00");
    }
}
