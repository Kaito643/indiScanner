//! Source connectors.
//!
//! Every source declares a [`Capability`] describing which IOC types it serves
//! and which operations it supports, so the engine only calls sources that can
//! actually answer a request. Phase 2 ports ThreatFox / URLhaus / OTX onto the
//! [`ThreatSource`] trait and splits their logic into `lookup` (enrichment) and
//! `search` (collection).

use crate::model::entity::ThreatEntity;
use crate::model::indicator::{IndicatorType, Observation};
use crate::model::request::RawIoc;
use anyhow::Result;
use async_trait::async_trait;

pub mod abuseipdb;
pub mod malwarebazaar;
pub mod otx;
pub mod threatfox;
pub mod urlhaus;
pub mod virustotal;

/// The abuse.ch `Auth-Key` shared by ThreatFox and URLhaus (both now require it).
/// Free key from <https://auth.abuse.ch/>. Returns `None` if unset/empty.
pub(crate) fn abuse_ch_key() -> Option<String> {
    std::env::var("ABUSE_CH_AUTH_KEY")
        .ok()
        .filter(|k| !k.is_empty())
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

    /// Collection: gather observations related to a threat entity.
    async fn search(&self, _entity: &ThreatEntity) -> Result<Vec<Observation>> {
        Ok(Vec::new())
    }
}
