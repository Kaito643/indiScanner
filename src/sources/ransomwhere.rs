//! Ransomwhere — crowdsourced, validated ransomware BTC payment addresses
//! (<https://ransomwhe.re/>). Open API, no key.
//!
//! The API is a single bulk export (~5 MB, ~11k addresses), so it is fetched
//! at most once per process and memoized; the cross-run disk cache then keeps
//! repeat queries for the same value off the network entirely.
//!
//! Serves both verbs: `lookup` answers "is this BTC address ransomware?",
//! `search` collects the addresses attributed to a ransomware family.

use super::{Capability, Operation, ThreatSource};
use crate::model::entity::ThreatEntity;
use crate::model::indicator::{IndicatorType, Observation};
use crate::model::request::{Filters, RawIoc};
use crate::util::{http_client, send_with_retry};
use anyhow::Result;
use async_trait::async_trait;
use log::{debug, info};
use reqwest::Client;
use serde::Deserialize;
use tokio::sync::OnceCell;

const API: &str = "https://api.ransomwhe.re/export";

/// Entries are manually validated before publication, but reporting is
/// crowdsourced — high confidence, short of a multi-engine verdict.
const CONFIDENCE: u8 = 85;

pub struct Ransomwhere {
    client: Client,
    entries: OnceCell<Vec<Entry>>,
}

impl Ransomwhere {
    pub fn new() -> Self {
        Self {
            client: http_client(),
            entries: OnceCell::new(),
        }
    }

    /// Fetch and memoize the full export (once per process).
    async fn entries(&self) -> Result<&[Entry]> {
        let entries = self
            .entries
            .get_or_try_init(|| async {
                info!("Ransomwhere: fetching full export");
                let http = send_with_retry(self.client.get(API))
                    .await?
                    .error_for_status()?;
                let export = http.json::<Export>().await?;
                debug!("Ransomwhere: {} entries loaded", export.result.len());
                anyhow::Ok(export.result)
            })
            .await?;
        Ok(entries)
    }

    fn to_observation(entry: &Entry) -> Observation {
        let mut obs = Observation::new(
            entry.address.clone(),
            IndicatorType::Btc,
            "Ransomwhere",
            CONFIDENCE,
        );
        obs.first_seen = entry.created_at.clone();
        if let Some(f) = &entry.family {
            obs.tags.push(f.clone());
            obs.context.insert("family".to_string(), f.clone());
        }
        if let Some(b) = &entry.blockchain {
            obs.context.insert("blockchain".to_string(), b.clone());
        }
        if let Some(sat) = entry.balance {
            obs.context
                .insert("balance_btc".to_string(), format!("{:.8}", sat / 1e8));
        }
        obs
    }
}

impl Default for Ransomwhere {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Deserialize)]
struct Export {
    result: Vec<Entry>,
}

#[derive(Deserialize)]
struct Entry {
    address: String,
    #[serde(default)]
    family: Option<String>,
    #[serde(default)]
    balance: Option<f64>,
    #[serde(default)]
    blockchain: Option<String>,
    #[serde(default, rename = "createdAt")]
    created_at: Option<String>,
}

#[async_trait]
impl ThreatSource for Ransomwhere {
    fn name(&self) -> &str {
        "Ransomwhere"
    }

    fn capabilities(&self) -> Capability {
        Capability {
            ioc_types: vec![IndicatorType::Btc],
            operations: vec![Operation::Lookup, Operation::Search],
        }
    }

    async fn lookup(&self, ioc: &RawIoc, ty: &IndicatorType) -> Result<Vec<Observation>> {
        if *ty != IndicatorType::Btc {
            return Ok(Vec::new());
        }
        // One observation even if an address recurs across reports: multiple
        // hits from the same dataset are not independent agreement.
        Ok(self
            .entries()
            .await?
            .iter()
            .find(|e| e.address == ioc.value)
            .map(Self::to_observation)
            .into_iter()
            .collect())
    }

    async fn search(&self, entity: &ThreatEntity, filters: &Filters) -> Result<Vec<Observation>> {
        let needle = entity.name.to_lowercase();
        let mut matches: Vec<Observation> = self
            .entries()
            .await?
            .iter()
            .filter(|e| {
                e.family
                    .as_deref()
                    .is_some_and(|f| f.to_lowercase().contains(&needle))
            })
            .map(Self::to_observation)
            .collect();
        // The dataset is local, so a user cap is a plain truncation.
        if let Some(max) = filters.max_results {
            if matches.len() > max {
                log::warn!(
                    "Ransomwhere: truncating {} results to --limit {max}",
                    matches.len()
                );
                matches.truncate(max);
            }
        }
        debug!(
            "Ransomwhere: {} addresses for '{}'",
            matches.len(),
            entity.name
        );
        Ok(matches)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry() -> Entry {
        Entry {
            address: "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".to_string(),
            family: Some("Netwalker (Mailto)".to_string()),
            balance: Some(126_686_348.0),
            blockchain: Some("bitcoin".to_string()),
            created_at: Some("07/08/2021 06:43:08".to_string()),
        }
    }

    #[test]
    fn observation_maps_family_and_balance() {
        let obs = Ransomwhere::to_observation(&entry());
        assert_eq!(obs.confidence, CONFIDENCE);
        assert_eq!(obs.indicator_type, IndicatorType::Btc);
        assert_eq!(
            obs.context.get("family").map(String::as_str),
            Some("Netwalker (Mailto)")
        );
        assert_eq!(
            obs.context.get("balance_btc").map(String::as_str),
            Some("1.26686348")
        );
        assert!(obs.tags.contains(&"Netwalker (Mailto)".to_string()));
        assert_eq!(obs.first_seen.as_deref(), Some("07/08/2021 06:43:08"));
    }

    #[test]
    fn export_parses_the_live_shape() {
        let json = r#"{"result":[{"address":"1abc","family":"LockBit","balance":0,
            "blockchain":"bitcoin","createdAt":"01/01/2022 00:00:00","updatedAt":"x"}]}"#;
        let export: Export = serde_json::from_str(json).unwrap();
        assert_eq!(export.result.len(), 1);
        assert_eq!(export.result[0].family.as_deref(), Some("LockBit"));
    }
}
