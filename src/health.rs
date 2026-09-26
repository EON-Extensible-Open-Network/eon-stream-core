// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 EON contributors
//
// Additional permission under GNU GPL version 3 section 7:
// see LICENSE-EXCEPTION.md (EON Module ABI Exception 1.0).

//! Remembering which addons are currently broken.
//!
//! A person with a dozen addons installed will, on any given evening, have one
//! or two that are down. Asking them every time makes every lookup as slow as
//! the slowest dead addon.
//!
//! So failures are remembered and a failing addon is skipped for a while. Three
//! properties matter, and each exists because the obvious implementation gets it
//! wrong:
//!
//! * **Backoff is bounded.** An addon that has been down for a week is retried
//!   every few minutes, not once a century.
//! * **A single failure is not a verdict.** One timeout on a flaky network must
//!   not sideline an addon that works.
//! * **Nothing is permanent.** A success clears the record immediately. An addon
//!   that comes back is used again on the next request, not after a cooldown.

use std::collections::HashMap;

/// Failures before an addon starts being skipped.
const TOLERATED_FAILURES: u32 = 2;

/// Shortest time an addon is skipped for.
const BASE_BACKOFF_SECS: u64 = 30;

/// Longest time an addon is skipped for, however badly it has behaved.
const MAX_BACKOFF_SECS: u64 = 600;

/// What is known about one addon's recent behaviour.
#[derive(Debug, Clone, Default)]
pub struct AddonHealth {
    /// Consecutive failures. Reset to zero by any success.
    pub consecutive_failures: u32,
    /// Total failures seen, for display. Never reset.
    pub total_failures: u32,
    /// Total successes seen, for display.
    pub total_successes: u32,
    /// When the last failure happened, as a Unix timestamp in seconds.
    pub last_failure_at: u64,
    /// What went wrong last, for showing a person why an addon is being skipped.
    pub last_error: Option<String>,
}

impl AddonHealth {
    /// How long this addon should be rested for, in seconds.
    #[must_use]
    pub fn backoff_secs(&self) -> u64 {
        if self.consecutive_failures <= TOLERATED_FAILURES {
            return 0;
        }
        // Double per failure past the tolerance, then stop doubling. Saturating
        // rather than wrapping: a large exponent must not fold back to a short
        // wait.
        let steps = self.consecutive_failures - TOLERATED_FAILURES - 1;
        BASE_BACKOFF_SECS
            .saturating_mul(1_u64.checked_shl(steps.min(16)).unwrap_or(u64::MAX))
            .min(MAX_BACKOFF_SECS)
    }

    /// Whether this addon is currently rested.
    #[must_use]
    pub fn is_resting(&self, now: u64) -> bool {
        let backoff = self.backoff_secs();
        backoff > 0 && now.saturating_sub(self.last_failure_at) < backoff
    }

    /// A short description for a list.
    #[must_use]
    pub fn display_state(&self, now: u64) -> String {
        if self.is_resting(now) {
            let remaining = self
                .backoff_secs()
                .saturating_sub(now.saturating_sub(self.last_failure_at));
            let reason = self.last_error.as_deref().unwrap_or("failing");
            format!("resting {remaining}s ({reason})")
        } else if self.consecutive_failures > 0 {
            format!("{} recent failure(s)", self.consecutive_failures)
        } else {
            "ok".to_owned()
        }
    }
}

/// Health of every addon that has been asked anything.
#[derive(Debug, Clone, Default)]
pub struct HealthTracker {
    addons: HashMap<String, AddonHealth>,
}

impl HealthTracker {
    /// A tracker with nothing recorded.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Note that an addon answered.
    pub fn record_success(&mut self, addon_id: &str) {
        let health = self.addons.entry(addon_id.to_owned()).or_default();
        health.consecutive_failures = 0;
        health.total_successes = health.total_successes.saturating_add(1);
        health.last_error = None;
    }

    /// Note that an addon failed.
    pub fn record_failure(&mut self, addon_id: &str, now: u64, error: &str) {
        let health = self.addons.entry(addon_id.to_owned()).or_default();
        health.consecutive_failures = health.consecutive_failures.saturating_add(1);
        health.total_failures = health.total_failures.saturating_add(1);
        health.last_failure_at = now;
        health.last_error = Some(error.to_owned());
    }

    /// Whether to skip an addon for now.
    #[must_use]
    pub fn should_skip(&self, addon_id: &str, now: u64) -> bool {
        self.addons
            .get(addon_id)
            .is_some_and(|health| health.is_resting(now))
    }

    /// What is known about one addon.
    #[must_use]
    pub fn get(&self, addon_id: &str) -> Option<&AddonHealth> {
        self.addons.get(addon_id)
    }

    /// Addons currently being rested, with how long is left.
    #[must_use]
    pub fn resting(&self, now: u64) -> Vec<(&str, u64)> {
        let mut resting: Vec<(&str, u64)> = self
            .addons
            .iter()
            .filter(|(_, health)| health.is_resting(now))
            .map(|(id, health)| {
                let remaining = health
                    .backoff_secs()
                    .saturating_sub(now.saturating_sub(health.last_failure_at));
                (id.as_str(), remaining)
            })
            .collect();
        resting.sort_unstable();
        resting
    }

    /// Forget everything, so every addon is tried again at once.
    pub fn reset(&mut self) {
        self.addons.clear();
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn one_failure_does_not_sideline_an_addon() {
        let mut tracker = HealthTracker::new();
        tracker.record_failure("a", 1_000, "timeout");
        assert!(!tracker.should_skip("a", 1_000));
    }

    #[test]
    fn repeated_failures_start_a_backoff() {
        let mut tracker = HealthTracker::new();
        for _ in 0..3 {
            tracker.record_failure("a", 1_000, "timeout");
        }
        assert!(tracker.should_skip("a", 1_000));
        assert!(tracker.should_skip("a", 1_020));
        // And it is retried once the rest is over.
        assert!(!tracker.should_skip("a", 1_000 + BASE_BACKOFF_SECS));
    }

    #[test]
    fn backoff_grows_but_is_capped() {
        let mut tracker = HealthTracker::new();
        for _ in 0..40 {
            tracker.record_failure("a", 1_000, "down");
        }
        let health = tracker.get("a").unwrap();
        assert_eq!(
            health.backoff_secs(),
            MAX_BACKOFF_SECS,
            "an addon down for a week must still be retried"
        );
    }

    #[test]
    fn a_success_clears_the_record_immediately() {
        let mut tracker = HealthTracker::new();
        for _ in 0..5 {
            tracker.record_failure("a", 1_000, "down");
        }
        assert!(tracker.should_skip("a", 1_000));

        tracker.record_success("a");
        assert!(
            !tracker.should_skip("a", 1_000),
            "an addon that came back must be used at once"
        );
        assert_eq!(tracker.get("a").unwrap().consecutive_failures, 0);
    }

    #[test]
    fn totals_are_kept_for_display() {
        let mut tracker = HealthTracker::new();
        tracker.record_failure("a", 1, "x");
        tracker.record_success("a");
        tracker.record_failure("a", 2, "y");
        let health = tracker.get("a").unwrap();
        assert_eq!(health.total_failures, 2);
        assert_eq!(health.total_successes, 1);
        assert_eq!(health.last_error.as_deref(), Some("y"));
    }

    #[test]
    fn an_unknown_addon_is_never_skipped() {
        let tracker = HealthTracker::new();
        assert!(!tracker.should_skip("never-asked", 1_000));
    }

    #[test]
    fn the_reason_is_visible_while_resting() {
        let mut tracker = HealthTracker::new();
        for _ in 0..4 {
            tracker.record_failure("a", 1_000, "HTTP 503");
        }
        let state = tracker.get("a").unwrap().display_state(1_005);
        assert!(state.contains("resting"), "{state}");
        assert!(state.contains("HTTP 503"), "{state}");
    }
}
