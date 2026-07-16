//! Source connectors.
//!
//! Every source declares a [`Capability`] describing which IOC types it serves
//! and which operations it supports, so the engine only calls sources that can
//! actually answer a request. Phase 2 ports ThreatFox / URLhaus / OTX onto the
//! [`ThreatSource`] trait and splits their logic into `lookup` (enrichment) and
//! `search` (collection).

use crate::model::entity::ThreatEntity;
use crate::model::indicator::{IndicatorType, Observation};
use crate::model::request::{Filters, RawIoc};
use anyhow::Result;
use async_trait::async_trait;

pub mod abuseipdb;
pub mod greynoise;
pub mod malwarebazaar;
pub mod otx;
pub mod ransomwhere;
pub mod shodan;
pub mod threatfox;
pub mod triage;
pub mod urlhaus;
pub mod virustotal;

/// The abuse.ch `Auth-Key` shared by ThreatFox and URLhaus (both now require it).
/// Free key from <https://auth.abuse.ch/>. Returns `None` if unset/empty.
pub(crate) fn abuse_ch_key() -> Option<String> {
    std::env::var("ABUSE_CH_AUTH_KEY")
        .ok()
        .filter(|k| !k.is_empty())
}

/// The effective per-source search cap: the user's `--limit` clamped to the
/// source's API maximum, or the API maximum itself when no limit was given.
pub(crate) fn search_cap(filters: &Filters, api_max: usize) -> usize {
    filters.max_results.unwrap_or(api_max).min(api_max)
}

/// Surface a possible truncation — a response that fills its cap probably has
/// more rows behind it, and silent caps read as full coverage.
pub(crate) fn warn_if_capped(source: &str, returned: usize, cap: usize) {
    if returned >= cap {
        log::warn!("{source}: {returned} results hit the cap of {cap}; more may exist");
    }
}

/// A human-readable hint for a failed abuse.ch HTTP status.
pub(crate) fn auth_hint(status: reqwest::StatusCode) -> &'static str {
    if status == reqwest::StatusCode::UNAUTHORIZED {
        "unauthorized — set ABUSE_CH_AUTH_KEY (free key from https://auth.abuse.ch/)"
    } else {
        "request failed"
    }
}

/// Build the active sources from config toggles. Open sources are included when
/// enabled; key-gated sources additionally require their credential to be set.
pub fn from_config(config: &crate::config::Config) -> Vec<Box<dyn ThreatSource>> {
    let toggles = &config.sources;
    let mut sources: Vec<Box<dyn ThreatSource>> = Vec::new();

    if toggles.threatfox {
        sources.push(Box::new(threatfox::ThreatFox::new()));
    }
    if toggles.urlhaus {
        sources.push(Box::new(urlhaus::URLhaus::new()));
    }
    if toggles.malwarebazaar {
        sources.push(Box::new(malwarebazaar::MalwareBazaar::new()));
    }
    if toggles.ransomwhere {
        sources.push(Box::new(ransomwhere::Ransomwhere::new()));
    }
    if toggles.otx {
        match otx::AlienVaultOTX::from_env() {
            Some(otx) => sources.push(Box::new(otx)),
            None => log::warn!("AlienVault OTX disabled: OTX_API_KEY not set."),
        }
    }
    if toggles.abuseipdb {
        match abuseipdb::AbuseIpdb::from_env() {
            Some(a) => sources.push(Box::new(a)),
            None => log::warn!("AbuseIPDB disabled: ABUSEIPDB_API_KEY not set."),
        }
    }
    if toggles.virustotal {
        match virustotal::VirusTotal::from_env() {
            Some(vt) => sources.push(Box::new(vt)),
            None => log::warn!("VirusTotal disabled: VT_API_KEY not set."),
        }
    }
    if toggles.greynoise {
        match greynoise::GreyNoise::from_env() {
            Some(g) => sources.push(Box::new(g)),
            None => log::warn!("GreyNoise disabled: GREYNOISE_API_KEY not set."),
        }
    }
    if toggles.shodan {
        match shodan::Shodan::from_env() {
            Some(s) => sources.push(Box::new(s)),
            None => log::warn!("Shodan disabled: SHODAN_API_KEY not set."),
        }
    }
    if toggles.triage {
        match triage::Triage::from_env() {
            Some(t) => sources.push(Box::new(t)),
            None => log::warn!("Triage disabled: TRIAGE_API_KEY not set."),
        }
    }
    sources
}

/// The ways a source can be queried.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    /// Look up context/reputation for a single known IOC value.
    Lookup,
    /// Search for IOCs related to a threat entity.
    Search,
    /// Pull a bulk feed.
    Feed,
}

/// What a source can do — matched against a request during routing.
#[derive(Debug, Clone, Default)]
pub struct Capability {
    /// IOC types this source serves.
    pub ioc_types: Vec<IndicatorType>,
    /// Operations this source supports.
    pub operations: Vec<Operation>,
}

impl Capability {
    /// Does this source support `op` for indicator type `ty`?
    pub fn serves(&self, ty: &IndicatorType, op: Operation) -> bool {
        self.operations.contains(&op) && self.ioc_types.contains(ty)
    }

    /// Does this source support `op` at all (type-agnostic, e.g. entity search)?
    pub fn supports(&self, op: Operation) -> bool {
        self.operations.contains(&op)
    }
}

/// A threat-intelligence source.
///
/// The default `lookup`/`search` implementations return nothing, so a source
/// only overrides the operations it actually supports (as declared in
/// [`Self::capabilities`]).
#[async_trait]
pub trait ThreatSource: Send + Sync {
    /// Display name (e.g. "ThreatFox").
    fn name(&self) -> &str;

    /// What this source can answer.
    fn capabilities(&self) -> Capability;

    /// Enrichment: gather observations about a single known IOC.
    async fn lookup(&self, _ioc: &RawIoc, _ty: &IndicatorType) -> Result<Vec<Observation>> {
        Ok(Vec::new())
    }

    /// Collection: gather observations related to a threat entity, honoring
    /// the request's [`Filters`] (result caps, lookback).
    async fn search(&self, _entity: &ThreatEntity, _filters: &Filters) -> Result<Vec<Observation>> {
        Ok(Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn search_cap_clamps_to_api_max() {
        let none = Filters::default();
        assert_eq!(search_cap(&none, 1000), 1000);
        let small = Filters {
            max_results: Some(50),
            ..Default::default()
        };
        assert_eq!(search_cap(&small, 1000), 50);
        let huge = Filters {
            max_results: Some(9999),
            ..Default::default()
        };
        assert_eq!(search_cap(&huge, 1000), 1000);
    }
}
