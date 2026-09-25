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

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use crate::types::Meta;

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
