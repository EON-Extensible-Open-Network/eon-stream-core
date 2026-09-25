// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 EON contributors
//
// Additional permission under GNU GPL version 3 section 7:
// see LICENSE-EXCEPTION.md (EON Module ABI Exception 1.0).

//! What addons return: catalogue entries, metadata, streams, subtitles.
//!
//! Every response is untrusted input (see `SECURITY.md`). The types below are
//! deliberately forgiving — almost every field is optional, because addons in
//! the wild omit things — but a missing field must never turn into a panic.

use serde::{Deserialize, Serialize};

/// One entry in a catalogue listing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetaPreview {
    /// Identifier, unique within the addon's id space.
    pub id: String,
    /// Content type.
    #[serde(rename = "type")]
    pub content_type: String,
    /// Display name.
    #[serde(default)]
    pub name: Option<String>,
    /// Poster image URL.
    #[serde(default)]
    pub poster: Option<String>,
    /// Shape hint for the poster: `poster`, `landscape` or `square`.
    #[serde(default, rename = "posterShape")]
    pub poster_shape: Option<String>,
    /// Short description.
    #[serde(default)]
    pub description: Option<String>,
    /// Release year or range, as the addon wrote it.
    #[serde(default, rename = "releaseInfo")]
    pub release_info: Option<String>,
    /// IMDb rating, as text because addons send both numbers and strings.
    #[serde(default, rename = "imdbRating")]
    pub imdb_rating: Option<String>,
}

impl MetaPreview {
    /// Name for display, falling back to the identifier.
    #[must_use]
    pub fn display_name(&self) -> &str {
        self.name.as_deref().unwrap_or(&self.id)
    }
}

/// Full metadata for one item.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Meta {
    /// Identifier.
    pub id: String,
    /// Content type.
    #[serde(rename = "type")]
    pub content_type: String,
    /// Display name.
    #[serde(default)]
    pub name: Option<String>,
    /// Long description.
    #[serde(default)]
    pub description: Option<String>,
    /// Poster image URL.
    #[serde(default)]
    pub poster: Option<String>,
    /// Background image URL.
    #[serde(default)]
    pub background: Option<String>,
    /// Logo image URL.
    #[serde(default)]
    pub logo: Option<String>,
    /// Release year or range.
    #[serde(default, rename = "releaseInfo")]
    pub release_info: Option<String>,
    /// Runtime, as the addon wrote it.
    #[serde(default)]
    pub runtime: Option<String>,
    /// Genres.
    #[serde(default, deserialize_with = "crate::serde_lax::null_to_default")]
    pub genres: Vec<String>,
    /// Cast.
    #[serde(default, deserialize_with = "crate::serde_lax::null_to_default")]
    pub cast: Vec<String>,
    /// Directors.
    #[serde(default, deserialize_with = "crate::serde_lax::null_to_default")]
    pub director: Vec<String>,
    /// Episodes or parts, for series and similar types.
    #[serde(default, deserialize_with = "crate::serde_lax::null_to_default")]
    pub videos: Vec<Video>,
}

impl Meta {
    /// Name for display, falling back to the identifier.
    #[must_use]
    pub fn display_name(&self) -> &str {
        self.name.as_deref().unwrap_or(&self.id)
    }

    /// Episodes of one season, in the order the addon sent them.
    #[must_use]
    pub fn season(&self, season: u32) -> Vec<&Video> {
        self.videos
            .iter()
            .filter(|v| v.season == Some(season))
            .collect()
    }

    /// Season numbers present, ascending, without duplicates.
    #[must_use]
    pub fn seasons(&self) -> Vec<u32> {
        let mut seasons: Vec<u32> = self.videos.iter().filter_map(|v| v.season).collect();
        seasons.sort_unstable();
        seasons.dedup();
        seasons
    }
}

/// One episode or part.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Video {
    /// Identifier to request streams for.
    pub id: String,
    /// Title.
    #[serde(default)]
    pub title: Option<String>,
    /// Season number.
    #[serde(default)]
    pub season: Option<u32>,
    /// Episode number within the season.
    #[serde(default)]
    pub episode: Option<u32>,
    /// Release timestamp, as the addon wrote it.
    #[serde(default)]
    pub released: Option<String>,
    /// Thumbnail URL.
    #[serde(default)]
    pub thumbnail: Option<String>,
}

impl Video {
    /// Title for display, falling back to `SxxEyy` and then to the identifier.
    #[must_use]
    pub fn display_title(&self) -> String {
        if let Some(title) = &self.title {
            return title.clone();
        }
        match (self.season, self.episode) {
            (Some(s), Some(e)) => format!("S{s:02}E{e:02}"),
            _ => self.id.clone(),
        }
    }
}

/// A playable source.
///
/// Exactly which field is populated decides how playback proceeds: a direct
/// URL, a BitTorrent info hash, or an external link the client opens in a
/// browser rather than playing.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Stream {
    /// Direct media URL.
    #[serde(default)]
    pub url: Option<String>,
    /// BitTorrent info hash.
    #[serde(default, rename = "infoHash")]
    pub info_hash: Option<String>,
    /// Index of the file inside the torrent.
    #[serde(default, rename = "fileIdx")]
    pub file_idx: Option<u32>,
    /// A link to open outside the player.
    #[serde(default, rename = "externalUrl")]
    pub external_url: Option<String>,
    /// YouTube video id.
    #[serde(default, rename = "ytId")]
    pub yt_id: Option<String>,
    /// Short label, usually quality or source.
    #[serde(default)]
    pub name: Option<String>,
    /// Longer description, often the file name and size.
    #[serde(default)]
    pub title: Option<String>,
    /// Free-form description used by some addons instead of `title`.
    #[serde(default)]
    pub description: Option<String>,
    /// Subtitle tracks the addon attaches to this source.
    #[serde(default, deserialize_with = "crate::serde_lax::null_to_default")]
    pub subtitles: Vec<Subtitle>,
}

/// How a [`Stream`] should be played.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamSource<'a> {
    /// Play this URL directly.
    Direct(&'a str),
    /// Fetch over BitTorrent, optionally a specific file within the torrent.
    Torrent {
        /// The torrent's info hash.
        info_hash: &'a str,
        /// Which file to play, when the addon says.
        file_idx: Option<u32>,
    },
    /// Hand off to the browser instead of playing.
    External(&'a str),
    /// A YouTube video id.
    YouTube(&'a str),
}

impl Stream {
    /// Work out how to play this stream.
    ///
    /// Returns `None` when the addon sent a stream object with nothing playable
    /// in it — which happens, and must not be treated as a crash.
    #[must_use]
    pub fn source(&self) -> Option<StreamSource<'_>> {
        if let Some(url) = self.url.as_deref().filter(|s| !s.is_empty()) {
            return Some(StreamSource::Direct(url));
        }
        if let Some(hash) = self.info_hash.as_deref().filter(|s| !s.is_empty()) {
            return Some(StreamSource::Torrent {
                info_hash: hash,
                file_idx: self.file_idx,
            });
        }
        if let Some(id) = self.yt_id.as_deref().filter(|s| !s.is_empty()) {
            return Some(StreamSource::YouTube(id));
        }
        if let Some(url) = self.external_url.as_deref().filter(|s| !s.is_empty()) {
            return Some(StreamSource::External(url));
        }
        None
    }

    /// A single line describing the stream, for a list.
    #[must_use]
    pub fn display_label(&self) -> String {
        let head = self.name.as_deref().unwrap_or("stream");
        match self.title.as_deref().or(self.description.as_deref()) {
            Some(detail) => {
                let detail = detail.replace('\n', " · ");
                format!("{head} — {detail}")
            }
            None => head.to_owned(),
        }
    }
}

/// A subtitle track.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Subtitle {
    /// Identifier within the addon.
    pub id: String,
    /// Where to fetch the subtitle file.
    pub url: String,
    /// Language code, as the addon wrote it.
    #[serde(default)]
    pub lang: Option<String>,
}

/// Envelope of a `catalog` response.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct MetasResponse {
    #[serde(default, deserialize_with = "crate::serde_lax::null_to_default")]
    pub metas: Vec<MetaPreview>,
}

/// Envelope of a `meta` response.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct MetaResponse {
    pub meta: Meta,
}

/// Envelope of a `stream` response.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct StreamsResponse {
    #[serde(default, deserialize_with = "crate::serde_lax::null_to_default")]
    pub streams: Vec<Stream>,
}

/// Envelope of a `subtitles` response.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct SubtitlesResponse {
    #[serde(default, deserialize_with = "crate::serde_lax::null_to_default")]
    pub subtitles: Vec<Subtitle>,
}
