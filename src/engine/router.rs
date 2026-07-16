//! Routing: turn a [`Request`] into concurrent calls to only the capable sources,
//! each wrapped with the disk cache and per-source rate limiter.

use crate::config::Config;
use crate::model::entity::ThreatEntity;
use crate::model::indicator::{IndicatorType, Observation};
use crate::model::request::{RawIoc, Request};
use crate::modules;
use crate::sources::{Operation, ThreatSource};
use crate::util::{Cache, RateLimiter};
use futures::future::join_all;
use log::{info, warn};

/// Dispatch a request to every capable source concurrently and return the
/// flattened observations. Source errors are logged and skipped.
pub async fn dispatch(
    sources: &[Box<dyn ThreatSource>],
    request: &Request,
    config: &Config,
    cache: &Cache,
    limiter: &RateLimiter,
) -> Vec<Observation> {
    match request {
        Request::Enrich(raw) => {
            let Some(det) = modules::detect(&raw.value) else {
                warn!(
                    "Could not classify IOC '{}'; no module recognized it.",
                    raw.value
                );
                return Vec::new();
            };
            info!("Classified '{}' as {:?}", det.canonical, det.indicator_type);
            let ioc = RawIoc::new(det.canonical);
            let ty = det.indicator_type;

            let futures = sources
                .iter()
                .filter(|s| s.capabilities().serves(&ty, Operation::Lookup))
                .map(|s| lookup_cached(s.as_ref(), &ioc, &ty, cache, limiter));
            flatten(join_all(futures).await)
        }

        Request::Collect { entity, .. } => {
            // Expand aliases into concrete entities (one search per term).
            let terms = config.resolve_aliases(&entity.name);
            info!("Collecting '{}' via terms: {:?}", entity.name, terms);
            let entities: Vec<ThreatEntity> = terms
                .into_iter()
                .map(|name| ThreatEntity::new(name, entity.kind))
                .collect();

            let mut futures = Vec::new();
            for source in sources {
                if source.capabilities().supports(Operation::Search) {
                    for ent in &entities {
                        futures.push(search_cached(source.as_ref(), ent, cache, limiter));
                    }
                }
            }
            flatten(join_all(futures).await)
        }
    }
}

/// Enrichment call wrapped with cache lookup + rate limiting.
async fn lookup_cached(
    source: &dyn ThreatSource,
    ioc: &RawIoc,
    ty: &IndicatorType,
    cache: &Cache,
    limiter: &RateLimiter,
) -> Vec<Observation> {
    let key = format!("{}|lookup|{}|{}", source.name(), ty.as_tag(), ioc.value);
    if let Some(hit) = cache.get(&key) {
        return hit;
    }
    limiter.acquire(source.name()).await;
    match source.lookup(ioc, ty).await {
        Ok(obs) => {
            cache.put(&key, &obs);
            obs
        }
        Err(e) => {
            warn!("{} lookup error: {e:#}", source.name());
            Vec::new()
        }
    }
}

/// Collection call wrapped with cache lookup + rate limiting.
async fn search_cached(
    source: &dyn ThreatSource,
    entity: &ThreatEntity,
    cache: &Cache,
    limiter: &RateLimiter,
) -> Vec<Observation> {
    let key = format!("{}|search|{}", source.name(), entity.name);
    if let Some(hit) = cache.get(&key) {
        return hit;
    }
    limiter.acquire(source.name()).await;
    match source.search(entity).await {
        Ok(obs) => {
            cache.put(&key, &obs);
            obs
        }
        Err(e) => {
            warn!("{} search error: {e:#}", source.name());
            Vec::new()
        }
    }
}

fn flatten(results: Vec<Vec<Observation>>) -> Vec<Observation> {
    results.into_iter().flatten().collect()
}
