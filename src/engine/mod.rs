//! Orchestration.
//!
//! The engine takes a [`Request`], routes it through the IOC-type modules to the
//! set of capable sources (see [`router`]), fans out concurrently — each call
//! wrapped with the disk cache and per-source rate limiter — and aggregates the
//! returned observations into consensus-scored indicators (see [`aggregate`]).

mod aggregate;
mod download;
mod router;
mod score;

pub use download::{DownloadReport, Outcome};

use crate::config::Config;
use crate::model::indicator::Indicator;
use crate::model::request::Request;
use crate::sources::ThreatSource;
use crate::util::{Cache, RateLimiter};
use anyhow::Result;
use std::path::Path;

/// The orchestrator: holds the active sources, config, cache, and rate limiter.
pub struct Engine {
    sources: Vec<Box<dyn ThreatSource>>,
    config: Config,
    cache: Cache,
    limiter: RateLimiter,
}

impl Engine {
    pub fn new(sources: Vec<Box<dyn ThreatSource>>, config: Config) -> Self {
        let cache = Cache::new(
            config.cache.dir.clone(),
            config.cache.ttl_seconds,
            config.cache.enabled,
        );
        let limiter = RateLimiter::with_overrides(
            config.ratelimit.default_ms,
            config.ratelimit.per_source.clone(),
        );
        Self {
            sources,
            config,
            cache,
            limiter,
        }
    }

    /// Run a request end-to-end: route → fan out (cache + rate limit) →
    /// aggregate → apply a Collect request's result filters (tag/type/confidence).
    pub async fn run(&self, request: Request) -> Result<Vec<Indicator>> {
        let filters = match &request {
            Request::Collect { filters, .. } => Some(filters.clone()),
            _ => None,
        };
        let observations = router::dispatch(
            &self.sources,
            &request,
            &self.config,
            &self.cache,
            &self.limiter,
        )
        .await;
        let mut indicators = aggregate::aggregate(observations, &self.config.weights);
        if let Some(f) = filters {
            indicators.retain(|ind| f.keeps(ind));
        }
        Ok(indicators)
    }

    /// Download raw malware samples for the given hashes into `dir`, optionally
    /// extracting each from its password-protected archive.
    pub async fn download(
        &self,
        hashes: &[String],
        dir: &Path,
        extract: bool,
    ) -> Vec<DownloadReport> {
        download::download(&self.sources, hashes, dir, extract, &self.limiter).await
    }
}
