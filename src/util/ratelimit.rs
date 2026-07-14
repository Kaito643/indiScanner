//! A simple per-key async rate limiter.
//!
//! Each source name is a key. Callers `acquire(key)` before making a request;
//! consecutive acquisitions for the same key are spaced at least `min_interval`
//! apart. Queued callers are scheduled cumulatively, so N concurrent requests to
//! one source are serialized across N intervals rather than all firing at once.

use std::collections::HashMap;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::time::Instant;

pub struct RateLimiter {
    min_interval: Duration,
    /// Per-key "next available" time.
    next: Mutex<HashMap<String, Instant>>,
}

impl RateLimiter {
    pub fn new(default_ms: u64) -> Self {
        Self {
            min_interval: Duration::from_millis(default_ms),
            next: Mutex::new(HashMap::new()),
        }
    }

    /// Block until it is this caller's turn to hit `key`.
    pub async fn acquire(&self, key: &str) {
        if self.min_interval.is_zero() {
            return;
        }
        let wait = {
            let mut guard = self.next.lock().await;
            let now = Instant::now();
            let scheduled = guard.get(key).copied().unwrap_or(now).max(now);
            guard.insert(key.to_string(), scheduled + self.min_interval);
            scheduled.saturating_duration_since(now)
        };
        if !wait.is_zero() {
            tokio::time::sleep(wait).await;
        }
    }
}
