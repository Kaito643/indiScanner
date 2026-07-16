//! VirusTotal v3 — multi-engine verdicts for files, URLs, domains and IPs
//! (`lookup` only; v3 search is a premium feature).
//!
//! Free tier is 4 requests/minute — paced by the per-source rate limit seeded
//! in [`crate::config::RateLimitConfig`]. Like AbuseIPDB, a clean verdict
//! (zero malicious/suspicious engines) emits no observation, so VT knowing a
//! value exists never inflates consensus.

use super::{Capability, Operation, ThreatSource};
use crate::model::indicator::{IndicatorType, Observation};
use crate::model::request::RawIoc;
use anyhow::Result;
use async_trait::async_trait;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use chrono::DateTime;
use log::{debug, warn};
use reqwest::Client;
use serde::Deserialize;
use std::env;

const API: &str = "https://www.virustotal.com/api/v3";

pub struct VirusTotal {
    client: Client,
    api_key: String,
}

impl VirusTotal {
    /// Build from `VT_API_KEY`; returns `None` if the key is absent/empty.
    pub fn from_env() -> Option<Self> {
        let api_key = env::var("VT_API_KEY").ok().filter(|k| !k.is_empty())?;
        Some(Self {
            client: Client::new(),
            api_key,
        })
    }

    /// The v3 object path for an indicator type. URLs are addressed by the
    /// unpadded URL-safe base64 of the URL itself.
    fn endpoint(ty: &IndicatorType, value: &str) -> Option<String> {
        Some(match ty {
            IndicatorType::IPv4 | IndicatorType::IPv6 => format!("ip_addresses/{value}"),
            IndicatorType::Domain => format!("domains/{value}"),
            IndicatorType::Url => format!("urls/{}", URL_SAFE_NO_PAD.encode(value)),
            IndicatorType::Md5 | IndicatorType::Sha1 | IndicatorType::Sha256 => {
                format!("files/{value}")
            }
            _ => return None,
        })
    }

    /// Saturating confidence from engine verdicts, mirroring the OTX curve:
    /// suspicious-only is weak (20); each malicious engine adds 10 on a base
    /// of 30, capping at 100 from 7 engines up.
    fn confidence_for(stats: &Stats) -> u8 {
        if stats.malicious == 0 {
            return 20;
        }
        (30 + stats.malicious.min(7) * 10).min(100) as u8
    }

    fn format_ts(ts: i64) -> Option<String> {
        DateTime::from_timestamp(ts, 0).map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
    }

    fn to_observation(ioc: &RawIoc, ty: &IndicatorType, attr: Attributes) -> Option<Observation> {
        let stats = attr.last_analysis_stats?;
        // Clean verdict — not an assertion of maliciousness; stay silent.
        if stats.malicious == 0 && stats.suspicious == 0 {
            return None;
        }

        let mut obs = Observation::new(
            ioc.value.clone(),
            ty.clone(),
            "VirusTotal",
            Self::confidence_for(&stats),
        );
        obs.first_seen = attr.first_submission_date.and_then(Self::format_ts);
        obs.last_seen = attr.last_analysis_date.and_then(Self::format_ts);
        obs.tags = attr.tags.unwrap_or_default();

        let total = stats.harmless + stats.malicious + stats.suspicious + stats.undetected;
        obs.context.insert(
            "detections".to_string(),
            format!("{}/{}", stats.malicious, total),
        );
        if let Some(label) = attr
            .popular_threat_classification
            .and_then(|c| c.suggested_threat_label)
        {
            obs.context.insert("malware".to_string(), label);
        }
        if let Some(r) = attr.reputation {
            obs.context.insert("reputation".to_string(), r.to_string());
        }
        if let Some(n) = attr.meaningful_name {
            obs.context.insert("file_name".to_string(), n);
        }
        if let Some(c) = attr.country {
            obs.context.insert("country".to_string(), c);
        }
        if let Some(a) = attr.as_owner {
            obs.context.insert("as_owner".to_string(), a);
        }
        Some(obs)
    }
}

#[derive(Deserialize)]
struct Response {
    data: Data,
}

#[derive(Deserialize)]
struct Data {
    attributes: Attributes,
}

#[derive(Deserialize)]
struct Attributes {
    #[serde(default)]
    last_analysis_stats: Option<Stats>,
    #[serde(default)]
    reputation: Option<i64>,
    #[serde(default)]
    tags: Option<Vec<String>>,
    #[serde(default)]
    first_submission_date: Option<i64>,
    #[serde(default)]
    last_analysis_date: Option<i64>,
    #[serde(default)]
    popular_threat_classification: Option<ThreatClassification>,
    #[serde(default)]
    meaningful_name: Option<String>,
    #[serde(default)]
    country: Option<String>,
    #[serde(default)]
    as_owner: Option<String>,
}

#[derive(Deserialize)]
struct Stats {
    #[serde(default)]
    harmless: u32,
    #[serde(default)]
    malicious: u32,
    #[serde(default)]
    suspicious: u32,
    #[serde(default)]
    undetected: u32,
}

#[derive(Deserialize)]
struct ThreatClassification {
    #[serde(default)]
    suggested_threat_label: Option<String>,
}

#[async_trait]
impl ThreatSource for VirusTotal {
    fn name(&self) -> &str {
        "VirusTotal"
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
        let Some(path) = Self::endpoint(ty, &ioc.value) else {
            return Ok(Vec::new());
        };
        debug!("VirusTotal GET {path}");

        let http = self
            .client
            .get(format!("{API}/{path}"))
            .header("x-apikey", &self.api_key)
            .send()
            .await?;

        match http.status() {
            s if s.is_success() => {}
            reqwest::StatusCode::NOT_FOUND => {
                // Unknown to VT — a normal empty answer, not an error.
                debug!("VirusTotal: {} not found", ioc.value);
                return Ok(Vec::new());
            }
            reqwest::StatusCode::TOO_MANY_REQUESTS => {
                warn!("VirusTotal quota exceeded (free tier: 4 req/min, 500/day)");
                return Ok(Vec::new());
            }
            s => {
                warn!("VirusTotal HTTP {s}");
                return Ok(Vec::new());
            }
        }

        let attr = http.json::<Response>().await?.data.attributes;
        Ok(Self::to_observation(ioc, ty, attr).into_iter().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stats(malicious: u32, suspicious: u32) -> Stats {
        Stats {
            harmless: 20,
            malicious,
            suspicious,
            undetected: 30,
        }
    }

    #[test]
    fn url_endpoint_uses_unpadded_base64() {
        let e = VirusTotal::endpoint(&IndicatorType::Url, "http://evil.com/a").unwrap();
        assert_eq!(
            e,
            format!("urls/{}", URL_SAFE_NO_PAD.encode("http://evil.com/a"))
        );
        assert!(!e.ends_with('='));
    }

    #[test]
    fn confidence_saturates_with_malicious_engines() {
        assert_eq!(VirusTotal::confidence_for(&stats(0, 2)), 20); // suspicious only
        assert_eq!(VirusTotal::confidence_for(&stats(1, 0)), 40);
        assert_eq!(VirusTotal::confidence_for(&stats(7, 0)), 100);
        assert_eq!(VirusTotal::confidence_for(&stats(60, 0)), 100);
    }

    #[test]
    fn clean_verdict_emits_no_observation() {
        let attr = Attributes {
            last_analysis_stats: Some(stats(0, 0)),
            reputation: Some(10),
            tags: None,
            first_submission_date: None,
            last_analysis_date: None,
            popular_threat_classification: None,
            meaningful_name: None,
            country: None,
            as_owner: None,
        };
        let ioc = RawIoc::new("1.2.3.4".to_string());
        assert!(VirusTotal::to_observation(&ioc, &IndicatorType::IPv4, attr).is_none());
    }

    #[test]
    fn malicious_verdict_maps_context_and_timestamps() {
        let attr = Attributes {
            last_analysis_stats: Some(stats(30, 1)),
            reputation: Some(-50),
            tags: Some(vec!["peexe".to_string()]),
            first_submission_date: Some(1_700_000_000),
            last_analysis_date: Some(1_750_000_000),
            popular_threat_classification: Some(ThreatClassification {
                suggested_threat_label: Some("trojan.emotet/krypt".to_string()),
            }),
            meaningful_name: Some("payload.exe".to_string()),
            country: None,
            as_owner: None,
        };
        let ioc = RawIoc::new("a".repeat(64));
        let obs = VirusTotal::to_observation(&ioc, &IndicatorType::Sha256, attr).unwrap();
        assert_eq!(obs.confidence, 100);
        assert_eq!(
            obs.context.get("detections").map(String::as_str),
            Some("30/81")
        );
        assert_eq!(
            obs.context.get("malware").map(String::as_str),
            Some("trojan.emotet/krypt")
        );
        assert_eq!(obs.first_seen.as_deref(), Some("2023-11-14 22:13:20 UTC"));
    }
}
