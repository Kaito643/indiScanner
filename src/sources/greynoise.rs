//! GreyNoise — internet-scanner context for IPs (community API, `lookup` only).
//!
//! GreyNoise watches internet-wide scan traffic and separates known benign
//! scanners (research projects, common business services) from malicious ones.
//! Following the AbuseIPDB convention, a benign / RIOT / unseen IP emits no
//! observation. A `malicious` classification maps to confidence 75 and
//! `suspicious` to 45; an unclassified-but-noisy IP (actively mass-scanning
//! the internet) is a weak signal at 25, tagged `internet-scanner`.

use super::{Capability, Operation, ThreatSource};
use crate::model::indicator::{IndicatorType, Observation};
use crate::model::request::RawIoc;
use anyhow::Result;
use async_trait::async_trait;
use log::{debug, warn};
use reqwest::Client;
use serde::Deserialize;
use std::env;

const API: &str = "https://api.greynoise.io/v3/community";

pub struct GreyNoise {
    client: Client,
    api_key: String,
}

impl GreyNoise {
    /// Build from `GREYNOISE_API_KEY`; returns `None` if the key is absent/empty.
    pub fn from_env() -> Option<Self> {
        let api_key = env::var("GREYNOISE_API_KEY")
            .ok()
            .filter(|k| !k.is_empty())?;
        Some(Self {
            client: Client::new(),
            api_key,
        })
    }

    fn to_observation(ioc: &RawIoc, ty: &IndicatorType, data: Community) -> Option<Observation> {
        let classification = data.classification.as_deref().unwrap_or("unknown");
        // Benign scanners and RIOT (known business services) are clean verdicts.
        if data.riot || classification == "benign" {
            return None;
        }
        let confidence = match classification {
            "malicious" => 75,
            "suspicious" => 45,
            // Not classified, but confirmed mass-scanning: weak signal.
            _ if data.noise => 25,
            _ => return None,
        };

        let mut obs = Observation::new(ioc.value.clone(), ty.clone(), "GreyNoise", confidence);
        obs.last_seen = data.last_seen;
        if data.noise {
            obs.tags.push("internet-scanner".to_string());
        }
        obs.context
            .insert("classification".to_string(), classification.to_string());
        if let Some(name) = data.name.filter(|n| n != "unknown") {
            obs.context.insert("actor".to_string(), name);
        }
        if let Some(link) = data.link {
            obs.context.insert("link".to_string(), link);
        }
        Some(obs)
    }
}

#[derive(Deserialize)]
struct Community {
    #[serde(default)]
    noise: bool,
    #[serde(default)]
    riot: bool,
    #[serde(default)]
    classification: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    link: Option<String>,
    #[serde(default)]
    last_seen: Option<String>,
}

#[async_trait]
impl ThreatSource for GreyNoise {
    fn name(&self) -> &str {
        "GreyNoise"
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
        debug!("GreyNoise GET {}", ioc.value);

        let http = self
            .client
            .get(format!("{API}/{}", ioc.value))
            .header("key", &self.api_key)
            .send()
            .await?;

        match http.status() {
            s if s.is_success() => {}
            reqwest::StatusCode::NOT_FOUND => {
                // GreyNoise has never seen this IP scanning — a normal empty answer.
                debug!("GreyNoise: {} not observed", ioc.value);
                return Ok(Vec::new());
            }
            reqwest::StatusCode::TOO_MANY_REQUESTS => {
                warn!("GreyNoise community quota exceeded (resets daily)");
                return Ok(Vec::new());
            }
            s => {
                warn!("GreyNoise HTTP {s}");
                return Ok(Vec::new());
            }
        }

        let data = http.json::<Community>().await?;
        Ok(Self::to_observation(ioc, ty, data).into_iter().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn community(classification: &str, noise: bool, riot: bool) -> Community {
        Community {
            noise,
            riot,
            classification: Some(classification.to_string()),
            name: Some("unknown".to_string()),
            link: None,
            last_seen: Some("2026-07-01".to_string()),
        }
    }

    fn ioc() -> RawIoc {
        RawIoc::new("1.2.3.4".to_string())
    }

    #[test]
    fn benign_and_riot_emit_no_observation() {
        let benign = community("benign", true, false);
        assert!(GreyNoise::to_observation(&ioc(), &IndicatorType::IPv4, benign).is_none());
        let riot = community("unknown", false, true);
        assert!(GreyNoise::to_observation(&ioc(), &IndicatorType::IPv4, riot).is_none());
    }

    #[test]
    fn quiet_unknown_emits_no_observation() {
        let quiet = community("unknown", false, false);
        assert!(GreyNoise::to_observation(&ioc(), &IndicatorType::IPv4, quiet).is_none());
    }

    #[test]
    fn malicious_maps_to_strong_observation() {
        let mut data = community("malicious", true, false);
        data.name = Some("SSH bruteforcer".to_string());
        let obs = GreyNoise::to_observation(&ioc(), &IndicatorType::IPv4, data).unwrap();
        assert_eq!(obs.confidence, 75);
        assert!(obs.tags.contains(&"internet-scanner".to_string()));
        assert_eq!(
            obs.context.get("actor").map(String::as_str),
            Some("SSH bruteforcer")
        );
        assert_eq!(obs.last_seen.as_deref(), Some("2026-07-01"));
    }

    #[test]
    fn suspicious_is_a_middle_signal() {
        let obs = GreyNoise::to_observation(
            &ioc(),
            &IndicatorType::IPv4,
            community("suspicious", true, false),
        )
        .unwrap();
        assert_eq!(obs.confidence, 45);
    }

    #[test]
    fn noisy_unknown_is_a_weak_signal() {
        let obs = GreyNoise::to_observation(
            &ioc(),
            &IndicatorType::IPv4,
            community("unknown", true, false),
        )
        .unwrap();
        assert_eq!(obs.confidence, 25);
        // "unknown" actor name is noise, not context.
        assert!(!obs.context.contains_key("actor"));
    }
}
