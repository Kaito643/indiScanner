//! Indicator values, the raw per-source [`Observation`], and the merged,
//! consensus-scored [`Indicator`].

use super::attack::AttackPattern;
use super::relationship::Relationship;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// The category of an indicator value.
///
/// Grouped by the IOC-type module that owns it: `network`, `file`, `email`.
/// `Other` carries the original source-provided label for anything not yet modelled.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IndicatorType {
    // network
    IPv4,
    IPv6,
    Domain,
    Url,
    // file
    Md5,
    Sha1,
    Sha256,
    Sha512,
    /// ssdeep fuzzy hash (`blocksize:chunk:double_chunk`).
    Ssdeep,
    // email
    Email,
    // crypto wallets
    Btc,
    Eth,
    Xmr,
    /// Not yet modelled; carries the original type label from the source.
    Other(String),
}

impl IndicatorType {
    /// A short, stable, lowercase tag — used in capability matching and output.
    pub fn as_tag(&self) -> &str {
        match self {
            IndicatorType::IPv4 => "ipv4",
            IndicatorType::IPv6 => "ipv6",
            IndicatorType::Domain => "domain",
            IndicatorType::Url => "url",
            IndicatorType::Md5 => "md5",
            IndicatorType::Sha1 => "sha1",
            IndicatorType::Sha256 => "sha256",
            IndicatorType::Sha512 => "sha512",
            IndicatorType::Ssdeep => "ssdeep",
            IndicatorType::Email => "email",
            IndicatorType::Btc => "btc",
            IndicatorType::Eth => "eth",
            IndicatorType::Xmr => "xmr",
            IndicatorType::Other(_) => "other",
        }
    }
}

/// One source's raw claim about a single value. Preserves provenance so a
/// consensus score is always traceable back to who reported what.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Observation {
    pub value: String,
    pub indicator_type: IndicatorType,
    /// The reporting source's name (e.g. "ThreatFox").
    pub source: String,
    /// Source-reported confidence, normalized to `0..=100`.
    pub confidence: u8,
    pub first_seen: Option<String>,
    pub last_seen: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    /// Free-form extra context keyed by field name (malware family, ASN, country, ...).
    #[serde(default)]
    pub context: BTreeMap<String, String>,
    /// Edges this source asserts between the observed value and other
    /// indicators (e.g. a host `Hosts` the URLs it serves).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub relationships: Vec<Relationship>,
}

impl Observation {
    /// Minimal constructor; optional fields default to empty.
    pub fn new(
        value: impl Into<String>,
        indicator_type: IndicatorType,
        source: impl Into<String>,
        confidence: u8,
    ) -> Self {
        Self {
            value: value.into(),
            indicator_type,
            source: source.into(),
            confidence,
            first_seen: None,
            last_seen: None,
            tags: Vec::new(),
            context: BTreeMap::new(),
            relationships: Vec::new(),
        }
    }

    /// The key used to group observations of the same value into one indicator.
    pub fn dedup_key(&self) -> (String, IndicatorType) {
        (self.value.clone(), self.indicator_type.clone())
    }
}

/// A merged, deduplicated indicator built from one or more [`Observation`]s.
///
/// The consensus `confidence` and unioned `tags` are derived by the aggregator
/// (Phase 2); every contributing observation is retained for provenance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Indicator {
    pub value: String,
    pub indicator_type: IndicatorType,
    /// Consensus confidence in `0..=100`, derived from `observations`.
    pub confidence: u8,
    /// Union of all tags across observations.
    pub tags: Vec<String>,
    /// ATT&CK techniques derived from the unioned tags (IOA layer).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attack_patterns: Vec<AttackPattern>,
    /// Union of all relationship edges asserted across observations.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub relationships: Vec<Relationship>,
    /// Every raw claim that contributed to this indicator (provenance).
    pub observations: Vec<Observation>,
}

impl Indicator {
    /// Distinct source names that reported this value.
    pub fn sources(&self) -> Vec<&str> {
        let mut seen = Vec::new();
        for o in &self.observations {
            if !seen.contains(&o.source.as_str()) {
                seen.push(o.source.as_str());
            }
        }
        seen
    }
}
