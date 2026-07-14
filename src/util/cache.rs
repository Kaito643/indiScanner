//! A cross-run, disk-backed response cache with TTL.
//!
//! Keyed by an opaque string (source + operation + query). Entries are stored as
//! JSON files named by a hash of the key, so repeated queries across runs avoid
//! re-hitting rate-limited APIs. A miss (absent, unreadable, or expired) simply
//! returns `None` and the caller queries live.

use crate::model::indicator::Observation;
use serde::{Deserialize, Serialize};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct Cache {
    dir: PathBuf,
    ttl_seconds: u64,
    enabled: bool,
}

#[derive(Serialize, Deserialize)]
struct Entry {
    stored_at: u64,
    observations: Vec<Observation>,
}

impl Cache {
    pub fn new(dir: impl Into<PathBuf>, ttl_seconds: u64, enabled: bool) -> Self {
        Self {
            dir: dir.into(),
            ttl_seconds,
            enabled,
        }
    }

    fn path_for(&self, key: &str) -> PathBuf {
        let mut h = DefaultHasher::new();
        key.hash(&mut h);
        self.dir.join(format!("{:016x}.json", h.finish()))
    }

    /// Return cached observations for `key` if present and not expired.
    pub fn get(&self, key: &str) -> Option<Vec<Observation>> {
        if !self.enabled {
            return None;
        }
        let text = std::fs::read_to_string(self.path_for(key)).ok()?;
        let entry: Entry = serde_json::from_str(&text).ok()?;
        if now_secs().saturating_sub(entry.stored_at) > self.ttl_seconds {
            return None;
        }
        Some(entry.observations)
    }

    /// Store observations for `key`. Best-effort: failures are ignored.
    pub fn put(&self, key: &str, observations: &[Observation]) {
        if !self.enabled {
            return;
        }
        if std::fs::create_dir_all(&self.dir).is_err() {
            return;
        }
        let entry = Entry {
            stored_at: now_secs(),
            observations: observations.to_vec(),
        };
        if let Ok(text) = serde_json::to_string(&entry) {
            let _ = std::fs::write(self.path_for(key), text);
        }
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
