// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 EON contributors
//
// Additional permission under GNU GPL version 3 section 7:
// see LICENSE-EXCEPTION.md (EON Module ABI Exception 1.0).

//! RFC 3339 timestamps.
//!
//! Key validity windows, revocation `issuedAt` / `nextUpdate` and release
//! dates are all RFC 3339 in the contracts, and all three are **security
//! decisions**: a timestamp read wrongly either expires a key early or honours
//! a revoked one.
//!
//! No date library. `chrono` and `time` are both fine crates, and neither is
//! worth a dependency for what is needed here: parse a fixed-shape UTC
//! timestamp into Unix seconds and print one back. The civil-date arithmetic
//! is the one genuinely subtle part, so it uses the standard days-from-civil
//! algorithm rather than a hand-rolled leap-year loop, and it is tested
//! against known epochs in both directions including the leap days that
//! usually catch this.
//!
//! What is deliberately *not* supported: local offsets other than `Z`, and
//! leap seconds. A contract timestamp is UTC; accepting `+03:00` would mean
//! two spellings of one instant in documents that get signed.

use std::fmt;

/// Why a timestamp could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimeError(String);

impl fmt::Display for TimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for TimeError {}

/// Parse `YYYY-MM-DDTHH:MM:SS[.frac]Z` into seconds since the Unix epoch.
///
/// A fractional part is accepted and truncated: it appears in real documents
/// and never matters at the resolution these decisions are made at.
///
/// # Errors
///
/// [`TimeError`] for any other shape, including a non-`Z` zone, an impossible
/// date such as 31 February, and an out-of-range component.
pub fn parse_rfc3339(text: &str) -> Result<i64, TimeError> {
    let bad = |why: &str| {
        Err(TimeError(format!(
            "'{text}' is not an RFC 3339 UTC time: {why}"
        )))
    };
    let text = text.trim();

    let Some(rest) = text.strip_suffix('Z').or_else(|| text.strip_suffix('z')) else {
        return bad("must end in Z; the contracts are UTC");
    };

    let Some((date, time)) = rest.split_once('T').or_else(|| rest.split_once('t')) else {
        return bad("expected a T between the date and the time");
    };

    let date: Vec<&str> = date.split('-').collect();
    if date.len() != 3 {
        return bad("expected YYYY-MM-DD");
    }
    // Widths are fixed, so `2026-1-1` is refused: a signed document must not
    // have two spellings of one day.
    if date[0].len() != 4 || date[1].len() != 2 || date[2].len() != 2 {
        return bad("date components must be zero-padded to YYYY-MM-DD");
    }
    let year = number(date[0], text)?;
    let month = number(date[1], text)?;
    let day = number(date[2], text)?;

    // Seconds may carry a fraction, which is truncated.
    let (time, _fraction) = match time.split_once('.') {
        Some((head, fraction)) => {
            if fraction.is_empty() || !fraction.chars().all(|c| c.is_ascii_digit()) {
                return bad("fractional seconds are not digits");
            }
            (head, Some(fraction))
        }
        None => (time, None),
    };
    let time: Vec<&str> = time.split(':').collect();
    if time.len() != 3 {
        return bad("expected HH:MM:SS");
    }
    if time.iter().any(|part| part.len() != 2) {
        return bad("time components must be zero-padded to HH:MM:SS");
    }
    let hour = number(time[0], text)?;
    let minute = number(time[1], text)?;
    let second = number(time[2], text)?;

    if !(1..=9999).contains(&year) {
        return bad("year is out of range");
    }
    if !(1..=12).contains(&month) {
        return bad("month is out of range");
    }
    if day < 1 || day > days_in_month(year, month) {
        return bad("day is out of range for that month");
    }
    if hour > 23 || minute > 59 {
        return bad("hour or minute is out of range");
    }
    // 60 would be a leap second. The contracts do not use them and pretending
    // to support one would mean two instants mapping to the same number.
    if second > 59 {
        return bad("second is out of range");
    }

    let days = days_from_civil(year, month, day);
    Ok(days * 86_400 + i64::from(hour) * 3600 + i64::from(minute) * 60 + i64::from(second))
}

/// Render Unix seconds as `YYYY-MM-DDTHH:MM:SSZ`.
///
/// Round-trips with [`parse_rfc3339`] for every value inside year 1..=9999;
/// outside that it saturates at the range ends rather than printing a
/// nonsensical date, because the only way to get there is a malformed input
/// that has already been reported.
#[must_use]
pub fn format_rfc3339(unix_seconds: i64) -> String {
    const MIN: i64 = -62_135_596_800; // 0001-01-01T00:00:00Z
    const MAX: i64 = 253_402_300_799; // 9999-12-31T23:59:59Z
    let seconds = unix_seconds.clamp(MIN, MAX);

    let days = seconds.div_euclid(86_400);
    let rest = seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = rest / 3600;
    let minute = (rest % 3600) / 60;
    let second = rest % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

fn number(text: &str, whole: &str) -> Result<u32, TimeError> {
    text.parse::<u32>()
        .map_err(|_| TimeError(format!("'{whole}' has a non-numeric component '{text}'")))
}

const fn is_leap(year: u32) -> bool {
    (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400)
}

const fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap(year) => 29,
        2 => 28,
        _ => 0,
    }
}

/// Days from 1970-01-01 to `year-month-day`.
///
/// Howard Hinnant's `days_from_civil`: shift the year so it starts in March,
/// which puts the leap day at the end of the year and removes every special
/// case from the arithmetic. Taken rather than invented because this is
/// exactly the function people get subtly wrong.
fn days_from_civil(year: u32, month: u32, day: u32) -> i64 {
    let y = i64::from(year) - i64::from(month <= 2);
    let era = y.div_euclid(400);
    let yoe = y - era * 400; // [0, 399]
    let m = i64::from(month);
    let doy = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + i64::from(day) - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * 146_097 + doe - 719_468
}

/// The inverse of [`days_from_civil`].
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11], March-based
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = mp + if mp < 10 { 3 } else { -9 }; // [1, 12]
    (y + i64::from(m <= 2), m, d)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn parses_known_epochs() {
        assert_eq!(parse_rfc3339("1970-01-01T00:00:00Z").unwrap(), 0);
        assert_eq!(parse_rfc3339("2000-01-01T00:00:00Z").unwrap(), 946_684_800);
        assert_eq!(
            parse_rfc3339("2026-01-01T00:00:00Z").unwrap(),
            1_767_225_600
        );
        // Before the epoch, which a notBefore on an imported key could carry.
        assert_eq!(parse_rfc3339("1969-12-31T23:59:59Z").unwrap(), -1);
    }

    #[test]
    fn round_trips_both_ways() {
        for text in [
            "1970-01-01T00:00:00Z",
            "2026-09-25T10:00:00Z",
            "2027-01-01T00:00:00Z",
            "2024-02-29T12:34:56Z", // leap day
            "2000-02-29T00:00:00Z", // leap day in a century divisible by 400
            "1999-12-31T23:59:59Z",
            "9999-12-31T23:59:59Z",
        ] {
            let seconds = parse_rfc3339(text).unwrap();
            assert_eq!(format_rfc3339(seconds), text, "round trip for {text}");
        }
    }

    #[test]
    fn leap_years_are_counted_the_way_the_calendar_does() {
        // 1900 is not a leap year; 2000 is. A hand-rolled `% 4` check gets the
        // first of these wrong and nothing notices for a century.
        assert!(parse_rfc3339("1900-02-29T00:00:00Z").is_err());
        assert!(parse_rfc3339("2000-02-29T00:00:00Z").is_ok());
        assert!(parse_rfc3339("2024-02-29T00:00:00Z").is_ok());
        assert!(parse_rfc3339("2026-02-29T00:00:00Z").is_err());
    }

    #[test]
    fn fractional_seconds_are_accepted_and_truncated() {
        assert_eq!(
            parse_rfc3339("2026-01-01T00:00:00.123Z").unwrap(),
            parse_rfc3339("2026-01-01T00:00:00Z").unwrap()
        );
    }

    #[test]
    fn only_utc_is_accepted() {
        // A zone offset would give one instant two spellings in a document
        // that gets signed.
        assert!(parse_rfc3339("2026-01-01T00:00:00+03:00").is_err());
        assert!(parse_rfc3339("2026-01-01T00:00:00").is_err());
        // Lowercase t and z are legal RFC 3339.
        assert!(parse_rfc3339("2026-01-01t00:00:00z").is_ok());
    }

    #[test]
    fn malformed_timestamps_are_refused() {
        for bad in [
            "",
            "2026",
            "2026-01-01",
            "2026-1-1T00:00:00Z",
            "2026-01-01T0:00:00Z",
            "2026-13-01T00:00:00Z",
            "2026-00-01T00:00:00Z",
            "2026-01-32T00:00:00Z",
            "2026-04-31T00:00:00Z",
            "2026-01-01T24:00:00Z",
            "2026-01-01T00:60:00Z",
            "2026-01-01T00:00:60Z",
            "0000-01-01T00:00:00Z",
            "yyyy-mm-ddT00:00:00Z",
            "2026-01-01T00:00:00.Z",
        ] {
            assert!(parse_rfc3339(bad).is_err(), "{bad} should be refused");
        }
    }

    #[test]
    fn formatting_saturates_rather_than_lying() {
        assert_eq!(format_rfc3339(i64::MAX), "9999-12-31T23:59:59Z");
        assert_eq!(format_rfc3339(i64::MIN), "0001-01-01T00:00:00Z");
    }

    #[test]
    fn every_day_of_a_leap_year_round_trips() {
        // Walks 2024 day by day: catches an off-by-one in either direction of
        // the civil-date conversion, which spot checks can miss.
        let start = parse_rfc3339("2024-01-01T00:00:00Z").unwrap();
        for day in 0..366 {
            let seconds = start + day * 86_400;
            let text = format_rfc3339(seconds);
            assert_eq!(parse_rfc3339(&text).unwrap(), seconds, "{text}");
        }
        assert_eq!(format_rfc3339(start + 365 * 86_400), "2024-12-31T00:00:00Z");
    }
}
