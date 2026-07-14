//! Orchestration.
//!
//! The engine takes a [`Request`], routes it through the IOC-type modules to the
//! set of capable sources (see [`router`]), fans out concurrently — each call
//! wrapped with the disk cache and per-source rate limiter — and aggregates the
//! returned observations into consensus-scored indicators (see [`aggregate`]).

mod aggregate;
mod router;
mod score;

use crate::config::Config;
use crate::model::indicator::Indicator;
use crate::model::request::Request;
use crate::sources::ThreatSource;
use crate::util::{Cache, RateLimiter};
use anyhow::Result;

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
        let limiter = RateLimiter::new(config.ratelimit.default_ms);
        Self {
            sources,
            config,
            cache,
            limiter,
        }
    }

    /// Run a request end-to-end: route → fan out (cache + rate limit) → aggregate.
    pub async fn run(&self, request: Request) -> Result<Vec<Indicator>> {
        let observations = router::dispatch(
            &self.sources,
            &request,
            &self.config,
            &self.cache,
            &self.limiter,
        )
        .await;
        Ok(aggregate::aggregate(observations))
    }
}
