//! ThreatFox (abuse.ch) — IOC search by value (`lookup`) and by tag (`search`).

use super::{Capability, Operation, ThreatSource};
use crate::model::entity::ThreatEntity;
use crate::model::indicator::{IndicatorType, Observation};
use crate::model::request::RawIoc;
use crate::util::{http_client, send_with_retry};
use anyhow::Result;
use async_trait::async_trait;
use log::{debug, warn};
use reqwest::Client;
use serde::Deserialize;
use serde_json::{json, Value};

const API: &str = "https://threatfox-api.abuse.ch/api/v1/";

pub struct ThreatFox {
    client: Client,
    auth_key: Option<String>,
}

impl Default for ThreatFox {
    fn default() -> Self {
        Self::new()
    }
}

impl ThreatFox {
    pub fn new() -> Self {
        Self {
            client: http_client(),
            auth_key: super::abuse_ch_key(),
        }
    }

    fn map_type(t: &str) -> IndicatorType {
        match t {
            "ip:port" | "ip" => IndicatorType::IPv4,
            "domain" => IndicatorType::Domain,
            "url" => IndicatorType::Url,
            "md5_hash" => IndicatorType::Md5,
            "sha1_hash" => IndicatorType::Sha1,
            "sha256_hash" => IndicatorType::Sha256,
            other => IndicatorType::Other(other.to_string()),
        }
    }

    fn to_observations(items: Vec<Item>) -> Vec<Observation> {
        items
            .into_iter()
            .map(|it| {
                let ty = Self::map_type(&it.ioc_type);

                // ThreatFox `ip:port` embeds the port in the value; split it into
                // context so the bare IP merges with the same IP from other sources.
                let (value, port) = match (it.ioc_type.as_str(), it.ioc.rsplit_once(':')) {
                    ("ip:port", Some((ip, p))) => (ip.to_string(), Some(p.to_string())),
                    _ => (it.ioc, None),
                };

                let mut obs =
                    Observation::new(value, ty, "ThreatFox", it.confidence_level.unwrap_or(50));
                obs.first_seen = it.first_seen;
                obs.last_seen = it.last_seen;
                obs.tags = it.tags.unwrap_or_default();
                if let Some(m) = it.malware_printable {
                    obs.context.insert("malware".to_string(), m);
                }
                if let Some(p) = port {
                    obs.context.insert("port".to_string(), p);
                }
                obs
            })
            .collect()
    }

    async fn query(&self, payload: Value) -> Result<Vec<Observation>> {
        let mut req = self.client.post(API).json(&payload);
        if let Some(key) = &self.auth_key {
            req = req.header("Auth-Key", key);
        }
        let http = send_with_retry(req).await?;
        if !http.status().is_success() {
            warn!(
                "ThreatFox HTTP {}: {}",
                http.status(),
                super::auth_hint(http.status())
            );
            return Ok(Vec::new());
        }

        let resp: Response = http.json().await?;
        if resp.query_status != "ok" {
            if !matches!(resp.query_status.as_str(), "no_result" | "no_results") {
                warn!("ThreatFox status: {}", resp.query_status);
            }
            return Ok(Vec::new());
        }
        // On success `data` is an array; on "no_result" ThreatFox puts a string
        // message here, so parse leniently and treat anything else as empty.
        let items: Vec<Item> = serde_json::from_value(resp.data).unwrap_or_default();
        Ok(Self::to_observations(items))
    }
}

#[derive(Deserialize)]
struct Response {
    query_status: String,
    #[serde(default)]
    data: Value,
}

#[derive(Deserialize)]
struct Item {
    ioc: String,
    ioc_type: String,
    #[serde(default)]
    first_seen: Option<String>,
    #[serde(default)]
    last_seen: Option<String>,
    #[serde(default)]
    confidence_level: Option<u8>,
    #[serde(default)]
    malware_printable: Option<String>,
    #[serde(default)]
    tags: Option<Vec<String>>,
}

#[async_trait]
impl ThreatSource for ThreatFox {
    fn name(&self) -> &str {
        "ThreatFox"
    }

    fn capabilities(&self) -> Capability {
        Capability {
            ioc_types: vec![
                IndicatorType::IPv4,
                IndicatorType::Domain,
                IndicatorType::Url,
                IndicatorType::Md5,
                IndicatorType::Sha256,
            ],
            operations: vec![Operation::Lookup, Operation::Search],
        }
    }

    async fn lookup(&self, ioc: &RawIoc, _ty: &IndicatorType) -> Result<Vec<Observation>> {
        debug!("ThreatFox search_ioc: {}", ioc.value);
        self.query(json!({ "query": "search_ioc", "search_term": ioc.value }))
            .await
    }

    async fn search(&self, entity: &ThreatEntity) -> Result<Vec<Observation>> {
        debug!("ThreatFox taginfo: {}", entity.name);
        self.query(json!({ "query": "taginfo", "tag": entity.name, "limit": 100 }))
            .await
    }
}
