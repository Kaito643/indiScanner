//! AbuseIPDB — IP reputation enrichment (`lookup` only, IPv4/IPv6).
//!
//! Returns an observation only when the IP actually has a non-zero abuse score;
//! a clean verdict is not an assertion of maliciousness, so it must not count as
//! consensus agreement.

use super::{Capability, Operation, ThreatSource};
use crate::model::indicator::{IndicatorType, Observation};
use crate::model::request::RawIoc;
use crate::util::{http_client, send_with_retry};
use anyhow::Result;
use async_trait::async_trait;
use log::{debug, warn};
use reqwest::Client;
use serde::Deserialize;
use std::env;

const API: &str = "https://api.abuseipdb.com/api/v2/check";

pub struct AbuseIpdb {
    client: Client,
    api_key: String,
}

impl AbuseIpdb {
    /// Build from `ABUSEIPDB_API_KEY`; returns `None` if the key is absent/empty.
    pub fn from_env() -> Option<Self> {
        let api_key = env::var("ABUSEIPDB_API_KEY")
            .ok()
            .filter(|k| !k.is_empty())?;
        Some(Self {
            client: http_client(),
            api_key,
        })
    }
}

#[derive(Deserialize)]
struct Response {
    data: Data,
}

#[derive(Deserialize)]
struct Data {
    #[serde(rename = "abuseConfidenceScore")]
    abuse_confidence_score: u8,
    #[serde(rename = "countryCode")]
    country_code: Option<String>,
    isp: Option<String>,
    domain: Option<String>,
    #[serde(rename = "usageType")]
    usage_type: Option<String>,
    #[serde(rename = "totalReports")]
    total_reports: Option<u32>,
    #[serde(rename = "lastReportedAt")]
    last_reported_at: Option<String>,
}

#[async_trait]
impl ThreatSource for AbuseIpdb {
    fn name(&self) -> &str {
        "AbuseIPDB"
    }

    fn capabilities(&self) -> Capability {
        Capability {
            ioc_types: vec![IndicatorType::IPv4, IndicatorType::IPv6],
            operations: vec![Operation::Lookup],
        }
    }

    async fn lookup(&self, ioc: &RawIoc, ty: &IndicatorType) -> Result<Vec<Observation>> {
        if !matches!(ty, IndicatorType::IPv4 | IndicatorType::IPv6) {
            return Ok(Vec::new());
        }
        debug!("AbuseIPDB check: {}", ioc.value);

        let http = send_with_retry(
            self.client
                .get(API)
                .header("Key", &self.api_key)
                .header("Accept", "application/json")
                .query(&[("ipAddress", ioc.value.as_str()), ("maxAgeInDays", "90")]),
        )
        .await?;

        if !http.status().is_success() {
            warn!("AbuseIPDB HTTP {}", http.status());
            return Ok(Vec::new());
        }

        let data = http.json::<Response>().await?.data;

        // A clean IP (score 0) is not evidence of badness — don't emit an
        // observation, so it never inflates consensus.
        if data.abuse_confidence_score == 0 {
            return Ok(Vec::new());
        }

        let mut obs = Observation::new(
            ioc.value.clone(),
            ty.clone(),
            "AbuseIPDB",
            data.abuse_confidence_score,
        );
        obs.last_seen = data.last_reported_at;
        if let Some(c) = data.country_code {
            obs.context.insert("country".to_string(), c);
        }
        if let Some(i) = data.isp {
            obs.context.insert("isp".to_string(), i);
        }
        if let Some(d) = data.domain {
            obs.context.insert("domain".to_string(), d);
        }
        if let Some(u) = data.usage_type {
            obs.context.insert("usage_type".to_string(), u);
        }
        if let Some(t) = data.total_reports {
            obs.context
                .insert("total_reports".to_string(), t.to_string());
        }
        Ok(vec![obs])
    }
}
