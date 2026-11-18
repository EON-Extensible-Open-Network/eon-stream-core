// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 EON contributors
//
// Additional permission under GNU GPL version 3 section 7:
// see LICENSE-EXCEPTION.md (EON Module ABI Exception 1.0).

//! Deserialisation that survives how addons actually behave.
//!
//! `#[serde(default)]` only applies when a field is **absent**. Addons in the
//! wild send an explicit `null` instead — Cinemeta, Stremio's own metadata
//! addon, does exactly that for `videos`, `genres` and friends on some items.
//! Rejecting those responses would mean refusing the most widely used addon
//! there is, and "compatible except with the reference addon" is not
//! compatibility.
//!
//! So every collection field accepts absent, `null`, or a value. The line we do
//! not cross: a field whose *type* is wrong is still an error. Being forgiving
//! about `null` is compatibility; guessing at malformed data would be hiding
//! bugs.

use serde::{Deserialize, Deserializer};

/// Accept `null` as the default value for a field.
///
/// # Errors
///
/// Propagates the deserialiser's error when the value is present but not of the
/// expected type.
pub(crate) fn null_to_default<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}

/// A list of words, however an addon sent it: a list, one word, or something
/// else entirely -- which reads as nothing rather than failing the whole entry.
///
/// Used for fields a catalogue entry may carry and nothing depends on, such
/// as its genres: one addon's odd shape must not cost a row its titles.
///
/// # Errors
///
/// Only when the input is not JSON at all.
pub(crate) fn words<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(match serde_json::Value::deserialize(deserializer)? {
        serde_json::Value::String(one) => vec![one],
        serde_json::Value::Array(many) => many
            .into_iter()
            .filter_map(|value| value.as_str().map(ToOwned::to_owned))
            .collect(),
        _ => Vec::new(),
    })
}

/// Text, however an addon sent it: a string, a list of strings (joined with
/// commas), or nothing.
///
/// # Errors
///
/// Only when the input is not JSON at all.
pub(crate) fn text<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(match serde_json::Value::deserialize(deserializer)? {
        serde_json::Value::String(one) if !one.trim().is_empty() => Some(one),
        serde_json::Value::Array(many) => {
            let parts: Vec<&str> = many.iter().filter_map(serde_json::Value::as_str).collect();
            (!parts.is_empty()).then(|| parts.join(", "))
        }
        _ => None,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use crate::types::{Meta, MetaPreview};

    #[test]
    fn genres_and_countries_are_read_in_any_shape_and_never_fail_an_entry() {
        let one: MetaPreview = serde_json::from_str(
            r#"{"id":"tt1","type":"movie","genres":["Drama","Isekai"],"country":"Turkey, Germany"}"#,
        )
        .unwrap();
        assert_eq!(one.genres, ["Drama", "Isekai"]);
        assert_eq!(one.country.as_deref(), Some("Turkey, Germany"));
        let word: MetaPreview = serde_json::from_str(
            r#"{"id":"tt2","type":"movie","genres":"Drama","country":["Japan","Korea"]}"#,
        )
        .unwrap();
        assert_eq!(word.genres, ["Drama"]);
        assert_eq!(word.country.as_deref(), Some("Japan, Korea"));
        let odd: MetaPreview = serde_json::from_str(
            r#"{"id":"tt3","type":"movie","genres":7,"country":{"a":1},"language":null}"#,
        )
        .unwrap();
        assert!(odd.genres.is_empty());
        assert!(odd.country.is_none() && odd.language.is_none());
    }

    #[test]
    fn null_collections_are_read_as_empty() {
        // Shape taken from a real Cinemeta series response.
        let json = r#"{
            "id": "tt0903747",
            "type": "series",
            "name": "Breaking Bad",
            "genres": null,
            "cast": null,
            "director": null,
            "videos": null
        }"#;
        let meta: Meta = serde_json::from_str(json).unwrap();
        assert!(meta.genres.is_empty());
        assert!(meta.videos.is_empty());
        assert!(meta.seasons().is_empty());
    }

    #[test]
    fn a_wrong_type_is_still_an_error() {
        let json = r#"{"id":"x","type":"movie","genres":"Drama"}"#;
        assert!(serde_json::from_str::<Meta>(json).is_err());
    }
}
