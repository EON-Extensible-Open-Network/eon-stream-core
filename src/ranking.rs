// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 EON contributors
//
// Additional permission under GNU GPL version 3 section 7:
// see LICENSE-EXCEPTION.md (EON Module ABI Exception 1.0).

//! Choosing between sources.
//!
//! Several addons answer the same question, each with several sources, and the
//! labels are free text written by whoever wrote the addon. So ranking reads
//! what is written rather than trusting a schema: resolution, codec, dynamic
//! range, audio layout and seeder counts all live in a human-written title.
//!
//! Two rules keep this honest:
//!
//! * **Nothing is invented.** A property that cannot be read from the label or a
//!   behaviour hint stays `None` and does not influence the order.
//! * **The user's addon order is the tiebreaker.** When two sources look equally
//!   good, the addon the user put first wins. That is a preference they
//!   expressed, and it outranks anything we guessed from a string.

use std::collections::HashSet;

use crate::types::Stream;

/// Video resolution, as far as it can be read from a label.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Resolution {
    /// Below 720p, or a label saying `cam`, `ts`, `screener`.
    Low,
    /// 720p.
    Hd,
    /// 1080p.
    FullHd,
    /// 1440p.
    QuadHd,
    /// 2160p and above.
    UltraHd,
}

impl Resolution {
    /// Read a resolution out of free text.
    #[must_use]
    pub fn from_label(label: &str) -> Option<Self> {
        let lower = label.to_ascii_lowercase();
        // Most specific first: "4k" and "2160" both mean UltraHd, and a label
        // can contain more than one number.
        for (needle, resolution) in [
            ("2160", Self::UltraHd),
            ("4k", Self::UltraHd),
            ("uhd", Self::UltraHd),
            ("1440", Self::QuadHd),
            ("2k", Self::QuadHd),
            ("1080", Self::FullHd),
            ("fhd", Self::FullHd),
            ("720", Self::Hd),
            ("480", Self::Low),
            ("360", Self::Low),
            ("cam", Self::Low),
            ("telesync", Self::Low),
            ("screener", Self::Low),
        ] {
            if lower.contains(needle) {
                return Some(resolution);
            }
        }
        None
    }
}

/// Dynamic range, which changes how a source looks more than resolution does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DynamicRange {
    /// Standard dynamic range, or unstated.
    Sdr,
    /// HDR10 or HLG.
    Hdr10,
    /// HDR10+.
    Hdr10Plus,
    /// Dolby Vision.
    DolbyVision,
}

impl DynamicRange {
    /// Read a dynamic range out of free text.
    #[must_use]
    pub fn from_label(label: &str) -> Self {
        let lower = label.to_ascii_lowercase();
        if lower.contains("dolby vision") || lower.contains("dovi") || lower.contains(" dv ") {
            Self::DolbyVision
        } else if lower.contains("hdr10+") || lower.contains("hdr10plus") {
            Self::Hdr10Plus
        } else if lower.contains("hdr") || lower.contains("hlg") {
            Self::Hdr10
        } else {
            Self::Sdr
        }
    }
}

/// Video codec, which decides whether a device can play a source at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Codec {
    /// H.264 / AVC — the safest bet everywhere.
    H264,
    /// H.265 / HEVC.
    H265,
    /// AV1.
    Av1,
    /// VP9.
    Vp9,
    /// Something else, or unstated.
    Other,
}

impl Codec {
    /// Read a codec out of free text.
    #[must_use]
    pub fn from_label(label: &str) -> Self {
        let lower = label.to_ascii_lowercase();
        if lower.contains("av1") {
            Self::Av1
        } else if lower.contains("hevc")
            || lower.contains("h265")
            || lower.contains("h.265")
            || lower.contains("x265")
        {
            Self::H265
        } else if lower.contains("vp9") {
            Self::Vp9
        } else if lower.contains("h264")
            || lower.contains("h.264")
            || lower.contains("x264")
            || lower.contains("avc")
        {
            Self::H264
        } else {
            Self::Other
        }
    }
}

/// What could be read about one source.
#[derive(Debug, Clone)]
pub struct StreamFacts {
    /// Resolution, if the label said.
    pub resolution: Option<Resolution>,
    /// Dynamic range.
    pub dynamic_range: DynamicRange,
    /// Video codec.
    pub codec: Codec,
    /// Size in bytes, from a hint or the label.
    pub size_bytes: Option<u64>,
    /// Seeder count, when the addon writes one.
    pub seeders: Option<u32>,
    /// Audio languages named in the label, lowercased.
    pub audio_languages: Vec<String>,
    /// Whether the addon attached subtitle tracks to this source.
    pub has_subtitles: bool,
    /// Whether the source needs headers to work.
    pub needs_headers: bool,
    /// Position of the providing addon in the user's list; lower is preferred.
    pub addon_rank: usize,
}

impl StreamFacts {
    /// Read everything readable from a source.
    #[must_use]
    pub fn read(stream: &Stream, addon_rank: usize) -> Self {
        // Both fields carry quality markers; addons are inconsistent about which.
        let label = [
            stream.name.as_deref().unwrap_or_default(),
            stream.title.as_deref().unwrap_or_default(),
            stream.description.as_deref().unwrap_or_default(),
        ]
        .join(" ");

        Self {
            resolution: Resolution::from_label(&label),
            dynamic_range: DynamicRange::from_label(&label),
            codec: Codec::from_label(&label),
            size_bytes: stream.size_bytes(),
            seeders: parse_seeders(&label),
            audio_languages: parse_languages(&label),
            has_subtitles: !stream.subtitles.is_empty(),
            needs_headers: !stream.request_headers().is_empty(),
            addon_rank,
        }
    }
}

/// How to order sources.
#[derive(Debug, Clone)]
pub struct RankingPreferences {
    /// Prefer higher resolution.
    pub prefer_higher_resolution: bool,
    /// Prefer HDR and Dolby Vision over SDR.
    pub prefer_high_dynamic_range: bool,
    /// Audio languages to favour, most wanted first, lowercased.
    pub preferred_audio_languages: Vec<String>,
    /// Favour sources that come with subtitles attached.
    pub prefer_sources_with_subtitles: bool,
    /// Prefer larger files, which usually means less compression. Off by
    /// default: on a slow connection the largest source is the worst choice.
    pub prefer_larger: bool,
    /// Drop sources whose resolution is below this.
    pub minimum_resolution: Option<Resolution>,
    /// Viewer's country, for skipping geo-restricted sources.
    pub country: Option<String>,
}

impl Default for RankingPreferences {
    fn default() -> Self {
        Self {
            prefer_higher_resolution: true,
            prefer_high_dynamic_range: true,
            preferred_audio_languages: Vec::new(),
            prefer_sources_with_subtitles: false,
            prefer_larger: false,
            minimum_resolution: None,
            country: None,
        }
    }
}

/// One ranked source, with what was read about it.
#[derive(Debug, Clone)]
pub struct RankedStream {
    /// Identifier of the addon that provided it.
    pub addon_id: String,
    /// The source.
    pub stream: Stream,
    /// What could be read.
    pub facts: StreamFacts,
}

impl RankedStream {
    /// A one-line summary, with the readable facts made explicit.
    #[must_use]
    pub fn display_label(&self) -> String {
        let mut marks = Vec::new();
        match self.facts.resolution {
            Some(Resolution::UltraHd) => marks.push("4K".to_owned()),
            Some(Resolution::QuadHd) => marks.push("1440p".to_owned()),
            Some(Resolution::FullHd) => marks.push("1080p".to_owned()),
            Some(Resolution::Hd) => marks.push("720p".to_owned()),
            Some(Resolution::Low) => marks.push("low".to_owned()),
            None => {}
        }
        match self.facts.dynamic_range {
            DynamicRange::DolbyVision => marks.push("DV".to_owned()),
            DynamicRange::Hdr10Plus => marks.push("HDR10+".to_owned()),
            DynamicRange::Hdr10 => marks.push("HDR".to_owned()),
            DynamicRange::Sdr => {}
        }
        match self.facts.codec {
            Codec::Av1 => marks.push("AV1".to_owned()),
            Codec::H265 => marks.push("HEVC".to_owned()),
            Codec::Vp9 => marks.push("VP9".to_owned()),
            Codec::H264 => marks.push("H.264".to_owned()),
            Codec::Other => {}
        }
        if let Some(size) = self.facts.size_bytes {
            marks.push(format_size(size));
        }
        if let Some(seeders) = self.facts.seeders {
            marks.push(format!("{seeders} seeders"));
        }
        if self.facts.has_subtitles {
            marks.push("subs".to_owned());
        }

        let detail = self.stream.display_label();
        if marks.is_empty() {
            detail
        } else {
            format!("[{}] {detail}", marks.join(" "))
        }
    }
}

/// Rank, deduplicate and filter sources from several addons.
///
/// `groups` is what the client returned: addon id paired with its sources, in
/// the user's addon order.
#[must_use]
pub fn rank(
    groups: &[(String, Vec<Stream>)],
    preferences: &RankingPreferences,
) -> Vec<RankedStream> {
    let mut ranked: Vec<RankedStream> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    for (addon_rank, (addon_id, streams)) in groups.iter().enumerate() {
        for stream in streams {
            // A source with nothing playable in it is noise, not a choice.
            if stream.source().is_none() {
                continue;
            }
            if let Some(country) = &preferences.country {
                if stream.is_geo_blocked_for(country) {
                    continue;
                }
            }
            let facts = StreamFacts::read(stream, addon_rank);
            if let (Some(minimum), Some(resolution)) =
                (preferences.minimum_resolution, facts.resolution)
            {
                if resolution < minimum {
                    continue;
                }
            }
            // Two addons indexing the same release is the normal case, not an
            // error: keep the first, which is the higher-priority addon.
            if let Some(key) = dedup_key(stream) {
                if !seen.insert(key) {
                    continue;
                }
            }
            ranked.push(RankedStream {
                addon_id: addon_id.clone(),
                stream: stream.clone(),
                facts,
            });
        }
    }

    ranked.sort_by(|a, b| compare(a, b, preferences));
    ranked
}

/// What makes two sources the same source.
///
/// An info hash is exact. A URL is exact. Anything else is not identified well
/// enough to risk hiding, so it is kept — dropping a source a person could have
/// used is worse than showing a near-duplicate.
fn dedup_key(stream: &Stream) -> Option<String> {
    if let Some(hash) = &stream.info_hash {
        return Some(format!(
            "ih:{}:{}",
            hash.to_ascii_lowercase(),
            stream.file_idx.unwrap_or(0)
        ));
    }
    if let Some(url) = &stream.url {
        return Some(format!("url:{url}"));
    }
    if let Some(id) = &stream.yt_id {
        return Some(format!("yt:{id}"));
    }
    None
}

/// Order two sources under the given preferences.
fn compare(
    a: &RankedStream,
    b: &RankedStream,
    preferences: &RankingPreferences,
) -> std::cmp::Ordering {
    use std::cmp::Ordering;

    if preferences.prefer_higher_resolution {
        // A stated resolution beats an unknown one: the addon that bothered to
        // say is more useful than the one that did not.
        let ordering = b.facts.resolution.cmp(&a.facts.resolution).then_with(|| {
            b.facts
                .resolution
                .is_some()
                .cmp(&a.facts.resolution.is_some())
        });
        if ordering != Ordering::Equal {
            return ordering;
        }
    }

    if preferences.prefer_high_dynamic_range {
        let ordering = b.facts.dynamic_range.cmp(&a.facts.dynamic_range);
        if ordering != Ordering::Equal {
            return ordering;
        }
    }

    if !preferences.preferred_audio_languages.is_empty() {
        let rank = |facts: &StreamFacts| {
            facts
                .audio_languages
                .iter()
                .filter_map(|language| {
                    preferences
                        .preferred_audio_languages
                        .iter()
                        .position(|wanted| wanted == language)
                })
                .min()
                .unwrap_or(usize::MAX)
        };
        let ordering = rank(&a.facts).cmp(&rank(&b.facts));
        if ordering != Ordering::Equal {
            return ordering;
        }
    }

    if preferences.prefer_sources_with_subtitles {
        let ordering = b.facts.has_subtitles.cmp(&a.facts.has_subtitles);
        if ordering != Ordering::Equal {
            return ordering;
        }
    }

    // More seeders means it is more likely to actually play.
    let ordering = b.facts.seeders.cmp(&a.facts.seeders);
    if ordering != Ordering::Equal {
        return ordering;
    }

    if preferences.prefer_larger {
        let ordering = b.facts.size_bytes.cmp(&a.facts.size_bytes);
        if ordering != Ordering::Equal {
            return ordering;
        }
    }

    // Last word goes to the order the user put their addons in.
    a.facts.addon_rank.cmp(&b.facts.addon_rank)
}

/// Read a seeder count out of a label: `👤 231`, `Seeds: 231`, `231 seeders`.
fn parse_seeders(label: &str) -> Option<u32> {
    let lower = label.to_ascii_lowercase();
    for marker in ["seeders", "seeds", "seed", "👤"] {
        if let Some(index) = lower.find(marker) {
            // The number can sit on either side of the marker.
            let after = lower.get(index + marker.len()..).unwrap_or_default();
            if let Some(value) = first_number(after) {
                return Some(value);
            }
            let before = lower.get(..index).unwrap_or_default();
            if let Some(value) = last_number(before) {
                return Some(value);
            }
        }
    }
    None
}

/// First run of digits in `text`, skipping separators.
fn first_number(text: &str) -> Option<u32> {
    let trimmed = text.trim_start_matches(|c: char| !c.is_ascii_digit());
    let digits: String = trimmed.chars().take_while(char::is_ascii_digit).collect();
    digits.parse().ok()
}

/// Last run of digits in `text`.
fn last_number(text: &str) -> Option<u32> {
    let trimmed = text.trim_end_matches(|c: char| !c.is_ascii_digit());
    let digits: String = trimmed
        .chars()
        .rev()
        .take_while(char::is_ascii_digit)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    digits.parse().ok()
}

/// Language names and codes that appear in source labels.
fn parse_languages(label: &str) -> Vec<String> {
    let lower = label.to_ascii_lowercase();
    const LANGUAGES: &[(&str, &str)] = &[
        ("turkish", "tur"),
        ("türkçe", "tur"),
        ("turkce", "tur"),
        ("english", "eng"),
        ("ingilizce", "eng"),
        ("german", "ger"),
        ("french", "fre"),
        ("spanish", "spa"),
        ("italian", "ita"),
        ("russian", "rus"),
        ("japanese", "jpn"),
        ("korean", "kor"),
        ("arabic", "ara"),
        ("multi", "multi"),
        ("dual", "multi"),
    ];
    let mut found: Vec<String> = Vec::new();
    for (needle, code) in LANGUAGES {
        if lower.contains(needle) && !found.iter().any(|f| f == code) {
            found.push((*code).to_owned());
        }
    }
    found
}

/// A size a person can read.
#[must_use]
pub fn format_size(bytes: u64) -> String {
    #[allow(clippy::cast_precision_loss)]
    let value = bytes as f64;
    if bytes >= 1_073_741_824 {
        format!("{:.1} GB", value / 1_073_741_824.0)
    } else if bytes >= 1_048_576 {
        format!("{:.0} MB", value / 1_048_576.0)
    } else {
        format!("{bytes} B")
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::types::{StreamBehaviorHints, Subtitle};

    fn stream(name: &str, title: &str) -> Stream {
        Stream {
            url: Some(format!("https://cdn.example.org/{name}-{title}.mkv")),
            name: Some(name.to_owned()),
            title: Some(title.to_owned()),
            ..Stream::default()
        }
    }

    #[test]
    fn reads_resolution_from_either_field() {
        assert_eq!(Resolution::from_label("4K HDR"), Some(Resolution::UltraHd));
        assert_eq!(
            Resolution::from_label("1080p x265"),
            Some(Resolution::FullHd)
        );
        assert_eq!(Resolution::from_label("720p"), Some(Resolution::Hd));
        assert_eq!(Resolution::from_label("CAM"), Some(Resolution::Low));
        assert_eq!(Resolution::from_label("who knows"), None);
    }

    #[test]
    fn reads_dynamic_range_and_codec() {
        assert_eq!(
            DynamicRange::from_label("2160p Dolby Vision"),
            DynamicRange::DolbyVision
        );
        assert_eq!(
            DynamicRange::from_label("1080p HDR10+"),
            DynamicRange::Hdr10Plus
        );
        assert_eq!(DynamicRange::from_label("1080p"), DynamicRange::Sdr);
        assert_eq!(Codec::from_label("x265 10bit"), Codec::H265);
        assert_eq!(Codec::from_label("AV1"), Codec::Av1);
        assert_eq!(Codec::from_label("nothing stated"), Codec::Other);
    }

    #[test]
    fn reads_size_from_a_human_written_title() {
        let mut s = stream("1080p", "movie.1080p.mkv\n4.2 GB");
        assert_eq!(s.size_bytes(), Some(4_509_715_660));
        s.title = Some("700MiB rip".into());
        assert_eq!(s.size_bytes(), Some(734_003_200));
        s.title = Some("no size here".into());
        assert_eq!(s.size_bytes(), None);
    }

    #[test]
    fn a_behaviour_hint_beats_a_parsed_size() {
        let mut s = stream("1080p", "says 4.2 GB in the title");
        s.behavior_hints.video_size = Some(123);
        assert_eq!(s.size_bytes(), Some(123));
    }

    #[test]
    fn reads_seeders_on_either_side_of_the_marker() {
        assert_eq!(parse_seeders("👤 231 💾 4.2 GB"), Some(231));
        assert_eq!(parse_seeders("Seeders: 42"), Some(42));
        assert_eq!(parse_seeders("15 seeders"), Some(15));
        assert_eq!(parse_seeders("no numbers"), None);
    }

    #[test]
    fn higher_resolution_comes_first() {
        let groups = vec![(
            "a".to_owned(),
            vec![
                stream("720p", "small"),
                stream("2160p", "huge"),
                stream("1080p", "medium"),
            ],
        )];
        let ranked = rank(&groups, &RankingPreferences::default());
        let order: Vec<Option<Resolution>> = ranked.iter().map(|r| r.facts.resolution).collect();
        assert_eq!(
            order,
            [
                Some(Resolution::UltraHd),
                Some(Resolution::FullHd),
                Some(Resolution::Hd)
            ]
        );
    }

    #[test]
    fn a_stated_resolution_beats_an_unknown_one() {
        let groups = vec![(
            "a".to_owned(),
            vec![stream("mystery", "no markers"), stream("720p", "stated")],
        )];
        let ranked = rank(&groups, &RankingPreferences::default());
        assert_eq!(ranked[0].facts.resolution, Some(Resolution::Hd));
    }

    #[test]
    fn the_same_release_from_two_addons_is_listed_once() {
        let shared = Stream {
            info_hash: Some("AABBCCDD".into()),
            file_idx: Some(0),
            name: Some("1080p".into()),
            ..Stream::default()
        };
        let groups = vec![
            ("first".to_owned(), vec![shared.clone()]),
            ("second".to_owned(), vec![shared]),
        ];
        let ranked = rank(&groups, &RankingPreferences::default());
        assert_eq!(ranked.len(), 1);
        // The addon the user put first is the one that survives.
        assert_eq!(ranked[0].addon_id, "first");
    }

    #[test]
    fn a_source_we_cannot_identify_is_never_hidden() {
        // No url, no hash, no id -- but a name. Two of them must both survive,
        // because dropping a usable source is worse than a near-duplicate.
        let vague = Stream {
            external_url: Some("https://example.org/watch".into()),
            name: Some("watch on site".into()),
            ..Stream::default()
        };
        let groups = vec![
            ("a".to_owned(), vec![vague.clone()]),
            ("b".to_owned(), vec![vague]),
        ];
        assert_eq!(rank(&groups, &RankingPreferences::default()).len(), 2);
    }

    #[test]
    fn a_source_with_nothing_playable_is_dropped() {
        let groups = vec![("a".to_owned(), vec![Stream::default()])];
        assert!(rank(&groups, &RankingPreferences::default()).is_empty());
    }

    #[test]
    fn geo_restricted_sources_are_skipped_for_that_viewer() {
        let mut restricted = stream("1080p", "only in one place");
        restricted.country_whitelist = vec!["usa".into()];
        let groups = vec![("a".to_owned(), vec![restricted])];

        let preferences = RankingPreferences {
            country: Some("tur".to_owned()),
            ..RankingPreferences::default()
        };
        assert!(rank(&groups, &preferences).is_empty());

        let allowed = RankingPreferences {
            country: Some("USA".to_owned()),
            ..RankingPreferences::default()
        };
        assert_eq!(rank(&groups, &allowed).len(), 1);
    }

    #[test]
    fn an_empty_whitelist_is_unknown_not_blocked() {
        let groups = vec![("a".to_owned(), vec![stream("1080p", "unstated")])];
        let preferences = RankingPreferences {
            country: Some("tur".to_owned()),
            ..RankingPreferences::default()
        };
        assert_eq!(rank(&groups, &preferences).len(), 1);
    }

    #[test]
    fn a_minimum_resolution_filters_but_keeps_the_unstated() {
        let groups = vec![(
            "a".to_owned(),
            vec![
                stream("480p", "poor"),
                stream("1080p", "good"),
                stream("mystery", "unstated"),
            ],
        )];
        let preferences = RankingPreferences {
            minimum_resolution: Some(Resolution::Hd),
            ..RankingPreferences::default()
        };
        let ranked = rank(&groups, &preferences);
        // 480p is dropped; the unstated one is kept, because we do not know it
        // is bad and refusing to show it would be guessing.
        assert_eq!(ranked.len(), 2);
    }

    #[test]
    fn preferred_audio_language_wins_over_addon_order() {
        let groups = vec![(
            "a".to_owned(),
            vec![
                stream("1080p", "English audio"),
                stream("1080p", "Turkish dublaj"),
            ],
        )];
        let preferences = RankingPreferences {
            preferred_audio_languages: vec!["tur".to_owned()],
            ..RankingPreferences::default()
        };
        let ranked = rank(&groups, &preferences);
        assert!(ranked[0].facts.audio_languages.contains(&"tur".to_owned()));
    }

    #[test]
    fn addon_order_is_the_final_tiebreaker() {
        let identical = |host: &str| Stream {
            url: Some(format!("https://{host}/same.mkv")),
            name: Some("1080p".into()),
            ..Stream::default()
        };
        let groups = vec![
            ("preferred".to_owned(), vec![identical("one.example.org")]),
            ("other".to_owned(), vec![identical("two.example.org")]),
        ];
        let ranked = rank(&groups, &RankingPreferences::default());
        assert_eq!(ranked[0].addon_id, "preferred");
    }

    #[test]
    fn the_label_makes_the_facts_visible() {
        let mut s = stream("2160p HDR x265", "movie.mkv\n12.4 GB 👤 87");
        s.subtitles = vec![Subtitle {
            id: "1".into(),
            url: "https://example.org/s.srt".into(),
            lang: Some("tur".into()),
        }];
        s.behavior_hints = StreamBehaviorHints::default();
        let ranked = rank(&[("a".to_owned(), vec![s])], &RankingPreferences::default());
        let label = ranked[0].display_label();
        for expected in ["4K", "HDR", "HEVC", "GB", "seeders", "subs"] {
            assert!(label.contains(expected), "missing {expected} in: {label}");
        }
    }

    #[test]
    fn sizes_are_formatted_for_people() {
        assert_eq!(format_size(4_509_715_660), "4.2 GB");
        assert_eq!(format_size(734_003_200), "700 MB");
        assert_eq!(format_size(512), "512 B");
    }
}
