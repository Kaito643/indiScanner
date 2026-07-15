//! A simple per-key async rate limiter.
//!
//! Each source name is a key. Callers `acquire(key)` before making a request;
//! consecutive acquisitions for the same key are spaced at least the key's
//! interval apart — the default interval, unless a per-source override is set
//! (e.g. VirusTotal's free tier at 4 requests/minute). Queued callers are
//! scheduled cumulatively, so N concurrent requests to one source are
//! serialized across N intervals rather than all firing at once.

use std::collections::HashMap;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::time::Instant;

pub struct RateLimiter {
    default_interval: Duration,
    /// Lowercased source name → interval override.
    overrides: HashMap<String, Duration>,
    /// Per-key "next available" time.
    next: Mutex<HashMap<String, Instant>>,
}

impl RateLimiter {
    pub fn new(default_ms: u64) -> Self {
        Self::with_overrides(default_ms, HashMap::new())
    }

    /// `per_source_ms` keys are matched case-insensitively against the source
    /// name passed to [`Self::acquire`], so config keys can stay lowercase.
    pub fn with_overrides(default_ms: u64, per_source_ms: HashMap<String, u64>) -> Self {
        Self {
            default_interval: Duration::from_millis(default_ms),
            overrides: per_source_ms
                .into_iter()
                .map(|(k, ms)| (k.to_lowercase(), Duration::from_millis(ms)))
                .collect(),
            next: Mutex::new(HashMap::new()),
        }
    }

    fn interval_for(&self, key: &str) -> Duration {
        self.overrides
            .get(&key.to_lowercase())
            .copied()
            .unwrap_or(self.default_interval)
    }

    /// Block until it is this caller's turn to hit `key`.
    pub async fn acquire(&self, key: &str) {
        let interval = self.interval_for(key);
        if interval.is_zero() {
            return;
        }
        let wait = {
            let mut guard = self.next.lock().await;
            let now = Instant::now();
            let scheduled = guard.get(key).copied().unwrap_or(now).max(now);
            guard.insert(key.to_string(), scheduled + interval);
            scheduled.saturating_duration_since(now)
        };
        if !wait.is_zero() {
            tokio::time::sleep(wait).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn override_wins_and_is_case_insensitive() {
        let rl = RateLimiter::with_overrides(
            1000,
            HashMap::from([("virustotal".to_string(), 15000u64)]),
        );
        assert_eq!(rl.interval_for("VirusTotal"), Duration::from_millis(15000));
        assert_eq!(rl.interval_for("ThreatFox"), Duration::from_millis(1000));
    }

    #[test]
    fn zero_default_still_honors_overrides() {
        let rl = RateLimiter::with_overrides(0, HashMap::from([("slow".to_string(), 500u64)]));
        assert_eq!(rl.interval_for("slow"), Duration::from_millis(500));
        assert!(rl.interval_for("fast").is_zero());
    }
}
