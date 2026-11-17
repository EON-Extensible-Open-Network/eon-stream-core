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
    /// Trailers, as the older Stremio shape: a `ytId` per entry.
    #[serde(default, deserialize_with = "crate::serde_lax::null_to_default")]
    pub trailers: Vec<Trailer>,
    /// Trailers, as the newer shape: a stream object each.
    ///
    /// Both exist in the wild and addons send one or the other, so both are
    /// read. A client that handled only the newer shape would show no trailer
    /// for most of Cinemeta.
    #[serde(
        default,
        rename = "trailerStreams",
        deserialize_with = "crate::serde_lax::null_to_default"
    )]
    pub trailer_streams: Vec<Stream>,
}

/// A trailer in the older `trailers` form.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Trailer {
    /// YouTube video id.
    #[serde(default, rename = "ytId")]
    pub yt_id: Option<String>,
    /// What kind of clip it is: `Trailer`, `Clip` and so on.
    #[serde(default, rename = "type")]
    pub kind: Option<String>,
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

    /// A URL for the trailer, if the addon offered one.
    ///
    /// Prefers the newer `trailerStreams` shape and falls back to a `ytId`,
    /// which is what Cinemeta still sends. A YouTube id becomes a watch URL
    /// for mpv's `ytdl` hook to resolve — the same path a YouTube *source*
    /// takes, so it needs `yt-dlp` present and fails the same way without it.
    #[must_use]
    pub fn trailer_url(&self) -> Option<String> {
        if let Some(url) = self
            .trailer_streams
            .iter()
            .find_map(|stream| match stream.source() {
                Some(StreamSource::Direct(url)) => Some(url.to_owned()),
                Some(StreamSource::YouTube(id)) => {
                    Some(format!("https://www.youtube.com/watch?v={id}"))
                }
                _ => None,
            })
        {
            return Some(url);
        }
        self.trailers
            .iter()
            .find_map(|trailer| trailer.yt_id.as_deref())
            .map(|id| format!("https://www.youtube.com/watch?v={id}"))
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
    /// Extra BitTorrent sources: tracker and DHT hints, as `tracker:` and
    /// `dht:` prefixed strings.
    #[serde(default, deserialize_with = "crate::serde_lax::null_to_default")]
    pub sources: Vec<String>,
    /// Countries this source is available in, as lowercase ISO 3166-1 alpha-3
    /// codes. Empty means no restriction the addon chose to declare.
    #[serde(
        default,
        rename = "countryWhitelist",
        deserialize_with = "crate::serde_lax::null_to_default"
    )]
    pub country_whitelist: Vec<String>,
    /// Behaviour hints for this source.
    #[serde(
        default,
        rename = "behaviorHints",
        deserialize_with = "crate::serde_lax::null_to_default"
    )]
    pub behavior_hints: StreamBehaviorHints,
}

/// Per-source behaviour hints.
///
/// These are the fields that decide whether a source can be handed to a player
/// as-is, what headers it needs, and which source to pick for the next episode.
/// Ignoring them is why a stream that works in one client fails in another.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamBehaviorHints {
    /// The source cannot be played by a plain web player: it needs specific
    /// headers, or it is a container a browser will not accept.
    ///
    /// mpv does not care about most of what makes a source "not web ready", so
    /// this is informational for us rather than disqualifying — but it is the
    /// signal that [`Self::proxy_headers`] probably matters.
    #[serde(default, rename = "notWebReady")]
    pub not_web_ready: bool,

    /// Headers the source needs. `request` headers are sent with the media
    /// request; `response` headers are what the addon expects back and are
    /// recorded but not acted upon.
    ///
    /// This is how an addon says "this CDN requires a Referer" — without it the
    /// source returns 403 and looks broken.
    #[serde(default, rename = "proxyHeaders")]
    pub proxy_headers: Option<ProxyHeaders>,

    /// Sources sharing a group are the same release, so the next episode can
    /// keep the same source automatically instead of asking again.
    #[serde(default, rename = "bingeGroup")]
    pub binge_group: Option<String>,

    /// The media file's name, when the addon knows it. Subtitle addons match on
    /// it, so it is passed through rather than dropped.
    #[serde(default)]
    pub filename: Option<String>,

    /// OpenSubtitles-style hash of the media file, for subtitle matching.
    #[serde(default, rename = "videoHash")]
    pub video_hash: Option<String>,

    /// Size of the media file in bytes, for subtitle matching and for ranking
    /// sources by size.
    #[serde(default, rename = "videoSize")]
    pub video_size: Option<u64>,
}

/// Headers an addon says a source needs.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyHeaders {
    /// Headers to send with the media request.
    #[serde(default, deserialize_with = "crate::serde_lax::null_to_default")]
    pub request: std::collections::BTreeMap<String, String>,
    /// Headers the addon expects in the response. Recorded for completeness;
    /// nothing acts on them.
    #[serde(default, deserialize_with = "crate::serde_lax::null_to_default")]
    pub response: std::collections::BTreeMap<String, String>,
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

    /// Headers the player must send with the media request.
    ///
    /// Without these an addon's source can answer 403 and look like a dead
    /// link, which is the most common "works in Stremio, not here" complaint.
    #[must_use]
    pub fn request_headers(&self) -> Vec<(&str, &str)> {
        self.behavior_hints
            .proxy_headers
            .as_ref()
            .map(|headers| {
                headers
                    .request
                    .iter()
                    .map(|(k, v)| (k.as_str(), v.as_str()))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The group this source belongs to, for keeping the same release across
    /// episodes.
    #[must_use]
    pub fn binge_group(&self) -> Option<&str> {
        self.behavior_hints.binge_group.as_deref()
    }

    /// Everything the addon told us that a subtitle addon can match on.
    #[must_use]
    pub fn subtitle_match(&self) -> SubtitleMatch<'_> {
        SubtitleMatch {
            filename: self.behavior_hints.filename.as_deref(),
            video_hash: self.behavior_hints.video_hash.as_deref(),
            video_size: self.behavior_hints.video_size,
        }
    }

    /// Whether this source is restricted to countries not including `country`.
    ///
    /// An empty whitelist means the addon declared no restriction, which is not
    /// the same as "available everywhere" — it is merely unknown, so it is
    /// treated as allowed.
    #[must_use]
    pub fn is_geo_blocked_for(&self, country: &str) -> bool {
        !self.country_whitelist.is_empty()
            && !self
                .country_whitelist
                .iter()
                .any(|c| c.eq_ignore_ascii_case(country))
    }

    /// Tracker URLs the addon supplied alongside a torrent source.
    #[must_use]
    pub fn trackers(&self) -> Vec<&str> {
        self.sources
            .iter()
            .filter_map(|s| s.strip_prefix("tracker:"))
            .collect()
    }

    /// Size in bytes, from the behaviour hint or parsed out of the label.
    ///
    /// Addons that do not set `videoSize` almost always write the size into the
    /// title, because a person choosing between sources wants to see it.
    #[must_use]
    pub fn size_bytes(&self) -> Option<u64> {
        if let Some(size) = self.behavior_hints.video_size {
            return Some(size);
        }
        // All three label fields, the same set `StreamFacts::read` uses for
        // resolution and codec. Addons are inconsistent about which one
        // carries the quality markers, and reading the size from only two of
        // them meant a source stating its size in `name` was treated as
        // stating no size at all -- which quietly broke sorting by size.
        for field in [
            self.title.as_deref(),
            self.description.as_deref(),
            self.name.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            if let Some(size) = parse_size(field) {
                return Some(size);
            }
        }
        None
    }
}

/// What a subtitle addon can match a file on.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SubtitleMatch<'a> {
    /// Media file name.
    pub filename: Option<&'a str>,
    /// OpenSubtitles-style hash.
    pub video_hash: Option<&'a str>,
    /// File size in bytes.
    pub video_size: Option<u64>,
}

impl SubtitleMatch<'_> {
    /// Whether there is anything here worth sending.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.filename.is_none() && self.video_hash.is_none() && self.video_size.is_none()
    }

    /// As protocol `extra` parameters for a subtitles request.
    #[must_use]
    pub fn as_extra(&self) -> Vec<(&'static str, String)> {
        let mut extra = Vec::new();
        if let Some(filename) = self.filename {
            extra.push(("filename", filename.to_owned()));
        }
        if let Some(hash) = self.video_hash {
            extra.push(("videoHash", hash.to_owned()));
        }
        if let Some(size) = self.video_size {
            extra.push(("videoSize", size.to_string()));
        }
        extra
    }
}

/// Pull a human-written size such as `4.2 GB` or `700MiB` out of a label.
fn parse_size(text: &str) -> Option<u64> {
    let bytes = text.as_bytes();
    for (index, _) in text.char_indices() {
        let rest = text.get(index..)?;
        let unit_at = |suffix: &str| {
            rest.get(..suffix.len())
                .is_some_and(|s| s.eq_ignore_ascii_case(suffix))
        };
        let multiplier: u64 = if unit_at("gib") || unit_at("gb") {
            1_073_741_824
        } else if unit_at("mib") || unit_at("mb") {
            1_048_576
        } else if unit_at("kib") || unit_at("kb") {
            1_024
        } else {
            continue;
        };

        // Walk back over an optional space and then the number.
        let mut start = index;
        while start > 0 && bytes[start - 1] == b' ' {
            start -= 1;
        }
        let number_end = start;
        while start > 0 && (bytes[start - 1].is_ascii_digit() || bytes[start - 1] == b'.') {
            start -= 1;
        }
        let number = text.get(start..number_end)?.trim();
        if number.is_empty() {
            continue;
        }
        let value: f64 = number.parse().ok()?;
        if value <= 0.0 {
            continue;
        }
        // Sizes come from addon text, so clamp rather than trusting the maths.
        #[allow(
            clippy::cast_precision_loss,
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss
        )]
        let scaled = (value * multiplier as f64).min(u64::MAX as f64) as u64;
        return Some(scaled);
    }
    None
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

/// One addon advertised by another addon's `addon_catalog` resource.
///
/// Addon discovery without a marketplace: an addon can point at others. This is
/// how a person finds addons before EON's own index exists (madde 8), and it is
/// read-only — nothing is installed without the user asking.
#[derive(Debug, Clone, Deserialize)]
pub struct AddonCatalogEntry {
    /// Where the advertised addon lives.
    #[serde(rename = "transportUrl")]
    pub transport_url: String,
    /// Its manifest, as the advertising addon copied it.
    ///
    /// Treated as a hint, not as truth: the manifest is re-fetched from the
    /// addon itself before anything is installed. An addon must not be able to
    /// lie about what another addon does.
    pub manifest: crate::manifest::AddonManifest,
}

/// Envelope of an `addon_catalog` response.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct AddonCatalogResponse {
    #[serde(default, deserialize_with = "crate::serde_lax::null_to_default")]
    pub addons: Vec<AddonCatalogEntry>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn a_trailer_is_read_from_either_shape() {
        // Both exist in the wild. Handling only the newer one would show no
        // trailer for most of Cinemeta, which still sends `ytId`.
        let older: Meta = serde_json::from_str(
            r#"{"id":"tt1","type":"movie","name":"A Film",
                "trailers":[{"ytId":"abc123","type":"Trailer"}]}"#,
        )
        .unwrap();
        assert_eq!(
            older.trailer_url().as_deref(),
            Some("https://www.youtube.com/watch?v=abc123")
        );

        let newer: Meta = serde_json::from_str(
            r#"{"id":"tt2","type":"movie","name":"B Film",
                "trailerStreams":[{"ytId":"xyz789","title":"Trailer"}]}"#,
        )
        .unwrap();
        assert_eq!(
            newer.trailer_url().as_deref(),
            Some("https://www.youtube.com/watch?v=xyz789")
        );
    }

    #[test]
    fn the_newer_shape_wins_when_an_addon_sends_both() {
        let both: Meta = serde_json::from_str(
            r#"{"id":"tt3","type":"movie","name":"C",
                "trailers":[{"ytId":"old"}],
                "trailerStreams":[{"url":"https://cdn.example.org/t.mp4"}]}"#,
        )
        .unwrap();
        assert_eq!(
            both.trailer_url().as_deref(),
            Some("https://cdn.example.org/t.mp4")
        );
    }

    #[test]
    fn no_trailer_is_none_rather_than_an_empty_url() {
        let bare: Meta = serde_json::from_str(r#"{"id":"tt4","type":"movie","name":"D"}"#).unwrap();
        assert!(bare.trailer_url().is_none());

        // A trailer entry with nothing playable in it is still no trailer.
        let useless: Meta = serde_json::from_str(
            r#"{"id":"tt5","type":"movie","name":"E","trailers":[{"type":"Clip"}]}"#,
        )
        .unwrap();
        assert!(useless.trailer_url().is_none());
    }

    #[test]
    fn a_size_in_the_name_field_is_read_like_one_in_the_title() {
        // Addons are inconsistent about which label field carries the quality
        // markers. Reading the size from only `title` and `description` meant
        // a source stating it in `name` counted as stating no size, which
        // silently broke sorting by size.
        let in_name: Stream =
            serde_json::from_str(r#"{"name":"Film 1080p 2.4 GB","url":"https://x/v.mkv"}"#)
                .unwrap();
        assert!(
            in_name.size_bytes().is_some(),
            "a size in `name` must count"
        );

        let in_title: Stream = serde_json::from_str(
            r#"{"name":"Film","title":"1080p 2.4 GB","url":"https://x/v.mkv"}"#,
        )
        .unwrap();
        assert_eq!(in_name.size_bytes(), in_title.size_bytes());

        // An explicit hint still wins over anything parsed from prose.
        let hinted: Stream = serde_json::from_str(
            r#"{"name":"Film 2.4 GB","url":"https://x/v.mkv",
                "behaviorHints":{"videoSize":1234}}"#,
        )
        .unwrap();
        assert_eq!(hinted.size_bytes(), Some(1234));

        let sizeless: Stream =
            serde_json::from_str(r#"{"name":"Film 1080p","url":"https://x/v.mkv"}"#).unwrap();
        assert!(sizeless.size_bytes().is_none());
    }

    #[test]
    fn a_null_trailer_list_is_read_as_empty() {
        // Cinemeta sends explicit nulls where arrays belong; see serde_lax.
        let nulled: Meta = serde_json::from_str(
            r#"{"id":"tt6","type":"movie","name":"F","trailers":null,"trailerStreams":null}"#,
        )
        .unwrap();
        assert!(nulled.trailer_url().is_none());
    }
}
