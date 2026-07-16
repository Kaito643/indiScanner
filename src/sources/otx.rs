//! AlienVault OTX — enrichment via the indicator "general" endpoint.
//!
//! OTX is enrichment-native: given an IOC it returns the pulses (community
//! reports) that reference it. `search` (pulse → per-indicator expansion) is
//! heavier and deferred, so OTX only advertises `Lookup`.

use super::{Capability, Operation, ThreatSource};
use crate::model::indicator::{IndicatorType, Observation};
use crate::model::request::RawIoc;
use crate::util::{http_client, send_with_retry};
use anyhow::Result;
use async_trait::async_trait;
use log::debug;
use reqwest::Client;
use serde::Deserialize;
use std::env;

pub struct AlienVaultOTX {
    client: Client,
    api_key: String,
}

impl AlienVaultOTX {
    /// Build from `OTX_API_KEY`; returns `None` if the key is absent/empty.
    pub fn from_env() -> Option<Self> {
        let api_key = env::var("OTX_API_KEY").ok().filter(|k| !k.is_empty())?;
        Some(Self {
            client: http_client(),
            api_key,
        })
    }

    /// The URL path section OTX uses for each indicator type.
    fn section(ty: &IndicatorType) -> Option<&'static str> {
        Some(match ty {
            IndicatorType::IPv4 => "IPv4",
            IndicatorType::IPv6 => "IPv6",
            IndicatorType::Domain => "domain",
            IndicatorType::Url => "url",
            IndicatorType::Md5 | IndicatorType::Sha1 | IndicatorType::Sha256 => "file",
            _ => return None,
        })
    }

    /// More corroborating pulses → higher confidence, saturating.
    fn confidence_for(pulse_count: u32) -> u8 {
        (30 + pulse_count.min(7) * 10).min(100) as u8
    }
}

#[derive(Deserialize)]
struct General {
    pulse_info: Option<PulseInfo>,
}

#[derive(Deserialize)]
struct PulseInfo {
    #[serde(default)]
    count: u32,
    #[serde(default)]
    pulses: Vec<Pulse>,
}

#[derive(Deserialize)]
struct Pulse {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    tags: Vec<String>,
}

#[async_trait]
impl ThreatSource for AlienVaultOTX {
    fn name(&self) -> &str {
        "AlienVault OTX"
    }

    fn capabilities(&self) -> Capability {
        Capability {
            ioc_types: vec![
                IndicatorType::IPv4,
                IndicatorType::IPv6,
                IndicatorType::Domain,
                IndicatorType::Url,
                IndicatorType::Md5,
                IndicatorType::Sha1,
                IndicatorType::Sha256,
            ],
            operations: vec![Operation::Lookup],
        }
    }

    async fn lookup(&self, ioc: &RawIoc, ty: &IndicatorType) -> Result<Vec<Observation>> {
        let Some(section) = Self::section(ty) else {
            return Ok(Vec::new());
        };
        let url = format!(
            "https://otx.alienvault.com/api/v1/indicators/{section}/{}/general",
            ioc.value
        );
        debug!("OTX general lookup: {url}");

        let general: General =
            send_with_retry(self.client.get(&url).header("X-OTX-API-KEY", &self.api_key))
                .await?
                .json()
                .await?;

        let info = match general.pulse_info {
            Some(i) if i.count > 0 => i,
            // No pulses reference this IOC — nothing to assert.
            _ => return Ok(Vec::new()),
        };

        let mut obs = Observation::new(
            ioc.value.clone(),
            ty.clone(),
            "AlienVault OTX",
            Self::confidence_for(info.count),
        );
        obs.context
            .insert("otx_pulse_count".to_string(), info.count.to_string());

        // Surface pulse names and their tags as context tags.
        for p in info.pulses.into_iter().take(10) {
            if let Some(name) = p.name {
                if !obs.tags.contains(&name) {
                    obs.tags.push(name);
                }
            }
            for t in p.tags {
                if !obs.tags.contains(&t) {
                    obs.tags.push(t);
                }
            }
        }

        Ok(vec![obs])
    }
}
