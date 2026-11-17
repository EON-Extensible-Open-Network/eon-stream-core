// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 EON contributors
//
// Additional permission under GNU GPL version 3 section 7:
// see LICENSE-EXCEPTION.md (EON Module ABI Exception 1.0).

//! The library: things a viewer kept.
//!
//! Stremio's equivalent is "My Library", and it is the most visible feature
//! this project did not have. The difference is where it lives: Stremio's
//! library is tied to an account and synced to a server, and this one is a
//! file beside the executable. No account exists to tie it to, and none is
//! planned for v1.
//!
//! ## Why this is not the watch history
//!
//! [`crate::history`] records what happened — where playback got to, what was
//! finished. This records what someone *chose*, which is a different thing
//! with different rules:
//!
//! * Finishing a film removes it from continue-watching and must not remove it
//!   from the library.
//! * Saving a series you have never played has no history to attach to.
//! * Clearing history to stop a shared machine showing what was watched must
//!   not throw away a carefully built list.
//!
//! Conflating them would mean one of those behaving wrongly, so they are two
//! files and two types.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{
    error::{Error, Result},
    fuzzy,
    types::MetaPreview,
};

/// One kept item.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LibraryEntry {
    /// Content type, as the addon names it.
    #[serde(rename = "type")]
    pub content_type: String,
    /// Item identifier within that type.
    pub id: String,
    /// Display name, stored rather than looked up again.
    ///
    /// A library that needs the network to show its own contents is a library
    /// that is empty on a train. The name is what a viewer recognises, so it
    /// is kept here even though it duplicates what an addon would return.
    pub name: String,
    /// Release year or range, when the addon said.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release_info: Option<String>,
    /// Poster URL, for an interface that will exist later. Never fetched here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub poster: Option<String>,
    /// Which addon it was found through, as a hint for where to look again.
    ///
    /// A hint and not a dependency: an addon can be removed, and the entry must
    /// survive that.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub addon_id: Option<String>,
    /// When it was kept, Unix seconds.
    pub saved_at: u64,
}

impl LibraryEntry {
    /// The key that identifies this item.
    #[must_use]
    pub fn key(&self) -> (&str, &str) {
        (&self.content_type, &self.id)
    }

    /// A line fit for a list.
    #[must_use]
    pub fn display_line(&self) -> String {
        match &self.release_info {
            Some(year) => format!("{}  ({year})  [{}]", self.name, self.content_type),
            None => format!("{}  [{}]", self.name, self.content_type),
        }
    }
}

/// How to order a library listing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LibraryOrder {
    /// Most recently kept first. The default, because the thing you just saved
    /// is the thing you are most likely looking for.
    Recent,
    /// Alphabetical by name, folded so `Çılgın` sorts with `C` rather than
    /// after `Z`.
    Name,
    /// Grouped by content type, then by name.
    Kind,
}

/// Everything a viewer kept.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Library {
    /// Schema version of the stored document.
    #[serde(default)]
    schema_version: u32,
    /// Entries, keyed by `type/id` so a reload cannot produce duplicates even
    /// if the file was edited by hand.
    #[serde(default)]
    entries: BTreeMap<String, LibraryEntry>,
}

impl Library {
    /// An empty library.
    #[must_use]
    pub fn new() -> Self {
        Self {
            schema_version: 0,
            entries: BTreeMap::new(),
        }
    }

    fn key_of(content_type: &str, id: &str) -> String {
        format!("{content_type}/{id}")
    }

    /// Keep an item. Returns whether it was newly added.
    ///
    /// Saving something already saved updates its stored name rather than
    /// duplicating it or refusing: a title can be corrected upstream, and the
    /// viewer should get the better name without losing their entry.
    pub fn save(&mut self, entry: LibraryEntry) -> bool {
        let key = Self::key_of(&entry.content_type, &entry.id);
        match self.entries.get_mut(&key) {
            Some(existing) => {
                existing.name = entry.name;
                existing.release_info = entry.release_info;
                existing.poster = entry.poster;
                // `saved_at` is deliberately left alone: the library's order is
                // when you chose something, not when you last re-saved it.
                false
            }
            None => {
                self.entries.insert(key, entry);
                true
            }
        }
    }

    /// Keep an item described by a catalogue entry.
    pub fn save_preview(
        &mut self,
        preview: &MetaPreview,
        addon_id: Option<&str>,
        now: u64,
    ) -> bool {
        self.save(LibraryEntry {
            content_type: preview.content_type.clone(),
            id: preview.id.clone(),
            name: preview.display_name().to_owned(),
            release_info: preview.release_info.clone(),
            poster: preview.poster.clone(),
            addon_id: addon_id.map(ToOwned::to_owned),
            saved_at: now,
        })
    }

    /// Stop keeping an item. Returns whether anything was removed.
    pub fn remove(&mut self, content_type: &str, id: &str) -> bool {
        self.entries
            .remove(&Self::key_of(content_type, id))
            .is_some()
    }

    /// Whether an item is kept.
    #[must_use]
    pub fn contains(&self, content_type: &str, id: &str) -> bool {
        self.entries.contains_key(&Self::key_of(content_type, id))
    }

    /// One entry.
    #[must_use]
    pub fn get(&self, content_type: &str, id: &str) -> Option<&LibraryEntry> {
        self.entries.get(&Self::key_of(content_type, id))
    }

    /// How many items are kept.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether nothing is kept.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Every entry, in the requested order.
    #[must_use]
    pub fn list(&self, order: LibraryOrder) -> Vec<&LibraryEntry> {
        let mut all: Vec<&LibraryEntry> = self.entries.values().collect();
        match order {
            LibraryOrder::Recent => {
                all.sort_by(|a, b| {
                    b.saved_at
                        .cmp(&a.saved_at)
                        // A stable tiebreak so two items saved in the same
                        // second do not swap places between listings.
                        .then_with(|| fuzzy::normalize(&a.name).cmp(&fuzzy::normalize(&b.name)))
                });
            }
            LibraryOrder::Name => {
                all.sort_by_key(|entry| fuzzy::normalize(&entry.name));
            }
            LibraryOrder::Kind => {
                all.sort_by(|a, b| {
                    a.content_type
                        .cmp(&b.content_type)
                        .then_with(|| fuzzy::normalize(&a.name).cmp(&fuzzy::normalize(&b.name)))
                });
            }
        }
        all
    }

    /// Entries of one content type, in the requested order.
    #[must_use]
    pub fn of_kind(&self, content_type: &str, order: LibraryOrder) -> Vec<&LibraryEntry> {
        self.list(order)
            .into_iter()
            .filter(|entry| entry.content_type == content_type)
            .collect()
    }

    /// Entries whose name matches `query`, best first.
    ///
    /// Uses the same approximate matching as search, so a library of two
    /// hundred items stays usable without exact recall of a title.
    #[must_use]
    pub fn search(&self, query: &str) -> Vec<&LibraryEntry> {
        let mut scored: Vec<(&LibraryEntry, f64)> = self
            .entries
            .values()
            .map(|entry| (entry, fuzzy::similarity(query, &entry.name)))
            .filter(|(_, score)| *score > 0.30)
            .collect();
        scored.sort_by(|a, b| {
            b.1.partial_cmp(&a.1)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.0.name.len().cmp(&b.0.name.len()))
        });
        scored.into_iter().map(|(entry, _)| entry).collect()
    }

    /// Every kept name, for use as a correction vocabulary.
    #[must_use]
    pub fn names(&self) -> Vec<&str> {
        self.entries.values().map(|e| e.name.as_str()).collect()
    }

    /// Content types present, sorted.
    #[must_use]
    pub fn kinds(&self) -> Vec<&str> {
        let mut kinds: Vec<&str> = self
            .entries
            .values()
            .map(|e| e.content_type.as_str())
            .collect();
        kinds.sort_unstable();
        kinds.dedup();
        kinds
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

    /// Read back a stored library.
    ///
    /// # Errors
    ///
    /// [`Error::Storage`] if the bytes are not a library this build reads.
    pub fn from_json(text: &str) -> Result<Self> {
        let library: Self = serde_json::from_str(text).map_err(|e| Error::Storage {
            message: e.to_string(),
        })?;
        if library.schema_version != 0 {
            return Err(Error::Storage {
                message: format!(
                    "library schemaVersion is {}, this build reads 0",
                    library.schema_version
                ),
            });
        }
        Ok(library)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn entry(id: &str, name: &str, kind: &str, saved_at: u64) -> LibraryEntry {
        LibraryEntry {
            content_type: kind.to_owned(),
            id: id.to_owned(),
            name: name.to_owned(),
            release_info: Some("2008".to_owned()),
            poster: None,
            addon_id: Some("com.linvo.cinemeta".to_owned()),
            saved_at,
        }
    }

    #[test]
    fn saving_and_removing() {
        let mut library = Library::new();
        assert!(library.is_empty());
        assert!(library.save(entry("tt0903747", "Breaking Bad", "series", 100)));
        assert!(library.contains("series", "tt0903747"));
        assert_eq!(library.len(), 1);

        // A different type with the same id is a different item.
        assert!(library.save(entry("tt0903747", "Breaking Bad", "movie", 100)));
        assert_eq!(library.len(), 2);

        assert!(library.remove("series", "tt0903747"));
        assert!(!library.remove("series", "tt0903747"));
        assert_eq!(library.len(), 1);
    }

    #[test]
    fn saving_twice_updates_the_name_and_keeps_the_date() {
        // A title can be corrected upstream; the viewer should get the better
        // name without their entry jumping to the top of the list.
        let mut library = Library::new();
        library.save(entry("tt1", "Breakng Bad", "series", 100));
        assert!(!library.save(entry("tt1", "Breaking Bad", "series", 999)));
        let stored = library.get("series", "tt1").expect("still there");
        assert_eq!(stored.name, "Breaking Bad");
        assert_eq!(stored.saved_at, 100, "order is when you chose it");
        assert_eq!(library.len(), 1);
    }

    #[test]
    fn recent_order_puts_the_newest_first() {
        let mut library = Library::new();
        library.save(entry("a", "Alpha", "movie", 100));
        library.save(entry("b", "Beta", "movie", 300));
        library.save(entry("c", "Gamma", "movie", 200));
        let names: Vec<&str> = library
            .list(LibraryOrder::Recent)
            .iter()
            .map(|e| e.name.as_str())
            .collect();
        assert_eq!(names, vec!["Beta", "Gamma", "Alpha"]);
    }

    #[test]
    fn name_order_folds_turkish_rather_than_exiling_it() {
        // `Çılgın` belongs with C, not after Z, which is what a byte sort does.
        let mut library = Library::new();
        library.save(entry("a", "Zebra", "movie", 1));
        library.save(entry("b", "Çılgın Hırsız", "movie", 2));
        library.save(entry("c", "Adam", "movie", 3));
        let names: Vec<&str> = library
            .list(LibraryOrder::Name)
            .iter()
            .map(|e| e.name.as_str())
            .collect();
        assert_eq!(names, vec!["Adam", "Çılgın Hırsız", "Zebra"]);
    }

    #[test]
    fn kind_order_groups_then_sorts() {
        let mut library = Library::new();
        library.save(entry("a", "Zebra", "series", 1));
        library.save(entry("b", "Apple", "movie", 2));
        library.save(entry("c", "Banana", "series", 3));
        let listed: Vec<(&str, &str)> = library
            .list(LibraryOrder::Kind)
            .iter()
            .map(|e| (e.content_type.as_str(), e.name.as_str()))
            .collect();
        assert_eq!(
            listed,
            vec![
                ("movie", "Apple"),
                ("series", "Banana"),
                ("series", "Zebra")
            ]
        );
    }

    #[test]
    fn filtering_by_kind() {
        let mut library = Library::new();
        library.save(entry("a", "A Film", "movie", 1));
        library.save(entry("b", "A Show", "series", 2));
        assert_eq!(library.of_kind("movie", LibraryOrder::Recent).len(), 1);
        assert_eq!(library.of_kind("series", LibraryOrder::Recent).len(), 1);
        assert_eq!(library.of_kind("music", LibraryOrder::Recent).len(), 0);
        assert_eq!(library.kinds(), vec!["movie", "series"]);
    }

    #[test]
    fn searching_a_library_survives_a_typo() {
        // The point of a library of two hundred items staying usable without
        // exact recall of a title.
        let mut library = Library::new();
        library.save(entry("a", "Better Call Saul", "series", 1));
        library.save(entry("b", "Breaking Bad", "series", 2));
        library.save(entry("c", "The Godfather", "movie", 3));

        let found = library.search("befer coll saol");
        assert_eq!(
            found.first().map(|e| e.name.as_str()),
            Some("Better Call Saul")
        );
        // Unrelated titles are left out rather than ranked last.
        assert!(found.iter().all(|e| e.name != "The Godfather"), "{found:?}");
        assert!(library.search("zzzzzzzzzz").is_empty());
    }

    #[test]
    fn a_turkish_title_is_searchable_without_its_diacritics() {
        let mut library = Library::new();
        library.save(entry("a", "Çılgın Hırsız", "movie", 1));
        let found = library.search("cilgin hirsiz");
        assert_eq!(found.len(), 1);
    }

    #[test]
    fn names_are_offered_as_a_correction_vocabulary() {
        let mut library = Library::new();
        library.save(entry("a", "Better Call Saul", "series", 1));
        let names = library.names();
        let suggestion = fuzzy::suggest("befer coll saol", &names).expect("a correction");
        assert_eq!(suggestion.corrected, "Better Call Saul");
    }

    #[test]
    fn a_catalogue_entry_can_be_kept_directly() {
        let preview = MetaPreview {
            id: "tt0903747".to_owned(),
            content_type: "series".to_owned(),
            name: Some("Breaking Bad".to_owned()),
            poster: Some("https://example.org/p.jpg".to_owned()),
            poster_shape: None,
            description: None,
            release_info: Some("2008-2013".to_owned()),
            imdb_rating: Some("9.5".to_owned()),
        };
        let mut library = Library::new();
        assert!(library.save_preview(&preview, Some("com.linvo.cinemeta"), 42));
        let stored = library.get("series", "tt0903747").expect("kept");
        assert_eq!(stored.name, "Breaking Bad");
        assert_eq!(stored.release_info.as_deref(), Some("2008-2013"));
        assert_eq!(stored.saved_at, 42);
    }

    #[test]
    fn round_trips_through_json_without_duplicating() {
        let mut library = Library::new();
        library.save(entry("a", "Alpha", "movie", 100));
        library.save(entry("b", "Beta", "series", 200));
        let text = library.to_json().unwrap();
        let back = Library::from_json(&text).unwrap();
        assert_eq!(back.len(), 2);
        assert!(back.contains("movie", "a"));
        assert!(back.contains("series", "b"));
    }

    #[test]
    fn an_unknown_schema_version_is_refused() {
        let json = r#"{"schema_version":99,"entries":{}}"#;
        assert!(Library::from_json(json).is_err());
    }

    #[test]
    fn a_display_line_names_the_kind() {
        let listed = entry("a", "Breaking Bad", "series", 1).display_line();
        assert!(listed.contains("Breaking Bad"));
        assert!(listed.contains("series"));
        assert!(listed.contains("2008"));
    }
}
