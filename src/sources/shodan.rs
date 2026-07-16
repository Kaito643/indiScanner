//! Shodan — internet-exposure context for IPs (`lookup` only).
//!
//! Shodan indexes what a host exposes to the internet: open ports, banners,
//! certificates and known CVEs. Mere exposure is not maliciousness, so a host
//! with only open ports emits no observation (the AbuseIPDB convention). An
//! observation is emitted when Shodan carries an actual badness signal — a
//! compromise-class tag (`malware`, `compromised`, `botnet`, ...) or known
//! vulnerabilities — and the exposure details ride along as context.
//!
//! Domain lookups (`/dns/domain`) need a membership plan, so only IPs are
//! served for now.

use super::{Capability, Operation, ThreatSource};
use crate::model::indicator::{IndicatorType, Observation};
use crate::model::request::RawIoc;
use anyhow::Result;
use async_trait::async_trait;
use log::{debug, warn};
use reqwest::Client;
use serde::Deserialize;
use std::env;

const API: &str = "https://api.shodan.io";

/// Shodan tags that assert compromise rather than mere exposure.
const BAD_TAGS: [&str; 6] = ["malware", "compromised", "botnet", "c2", "spam", "phishing"];

/// Cap the CVE list carried in context so one unpatched box stays readable.
const MAX_VULNS_LISTED: usize = 10;

pub struct Shodan {
    client: Client,
    api_key: String,
}

impl Shodan {
    /// Build from `SHODAN_API_KEY`; returns `None` if the key is absent/empty.
    pub fn from_env() -> Option<Self> {
        let api_key = env::var("SHODAN_API_KEY").ok().filter(|k| !k.is_empty())?;
        Some(Self {
            client: Client::new(),
            api_key,
        })
    }

    /// Vulnerable-but-not-flagged hosts scale gently with CVE count and stay
    /// below the "actively compromised" band: vulnerable ≠ malicious.
    fn confidence_for(vuln_count: usize, has_bad_tag: bool) -> u8 {
        if has_bad_tag {
            return 75;
        }
        (30 + vuln_count.min(7) * 5) as u8
    }

    fn to_observation(ioc: &RawIoc, ty: &IndicatorType, host: Host) -> Option<Observation> {
        let has_bad_tag = host
            .tags
            .iter()
            .any(|t| BAD_TAGS.contains(&t.to_lowercase().as_str()));
        // Exposure alone (open ports, banners) is not a badness verdict.
        if host.vulns.is_empty() && !has_bad_tag {
            return None;
        }

        let mut obs = Observation::new(
            ioc.value.clone(),
            ty.clone(),
            "Shodan",
            Self::confidence_for(host.vulns.len(), has_bad_tag),
        );
        obs.last_seen = host.last_update;
        obs.tags = host.tags;

        let mut ports = host.ports;
        ports.sort_unstable();
        if !ports.is_empty() {
            let list: Vec<String> = ports.iter().map(u16::to_string).collect();
            obs.context.insert("open_ports".to_string(), list.join(","));
        }
        if !host.vulns.is_empty() {
            let mut vulns = host.vulns;
            vulns.sort_unstable();
            let extra = vulns.len().saturating_sub(MAX_VULNS_LISTED);
            vulns.truncate(MAX_VULNS_LISTED);
            let mut listed = vulns.join(",");
            if extra > 0 {
                listed.push_str(&format!(" (+{extra} more)"));
            }
            obs.context.insert("vulns".to_string(), listed);
        }
        if !host.hostnames.is_empty() {
            obs.context
                .insert("hostnames".to_string(), host.hostnames.join(","));
        }
        if let Some(o) = host.org {
            obs.context.insert("org".to_string(), o);
        }
        if let Some(i) = host.isp {
            obs.context.insert("isp".to_string(), i);
        }
        if let Some(a) = host.asn {
            obs.context.insert("asn".to_string(), a);
        }
        if let Some(c) = host.country_name {
            obs.context.insert("country".to_string(), c);
        }
        if let Some(os) = host.os {
            obs.context.insert("os".to_string(), os);
        }
        Some(obs)
    }
}

#[derive(Deserialize)]
struct Host {
    #[serde(default)]
    ports: Vec<u16>,
    #[serde(default)]
    hostnames: Vec<String>,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    vulns: Vec<String>,
    #[serde(default)]
    org: Option<String>,
    #[serde(default)]
    isp: Option<String>,
    #[serde(default)]
    asn: Option<String>,
    #[serde(default)]
    os: Option<String>,
    #[serde(default)]
    country_name: Option<String>,
    #[serde(default)]
    last_update: Option<String>,
}

#[async_trait]
impl ThreatSource for Shodan {
    fn name(&self) -> &str {
        "Shodan"
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
        debug!("Shodan GET host/{}", ioc.value);

        let http = self
            .client
            .get(format!("{API}/shodan/host/{}", ioc.value))
            .query(&[("key", self.api_key.as_str()), ("minify", "true")])
            .send()
            .await?;

        match http.status() {
            s if s.is_success() => {}
            reqwest::StatusCode::NOT_FOUND => {
                // Shodan hasn't indexed this host — a normal empty answer.
                debug!("Shodan: {} not found", ioc.value);
                return Ok(Vec::new());
            }
            reqwest::StatusCode::UNAUTHORIZED => {
                warn!("Shodan unauthorized — check SHODAN_API_KEY");
                return Ok(Vec::new());
            }
            reqwest::StatusCode::TOO_MANY_REQUESTS => {
                warn!("Shodan rate limit exceeded (1 req/sec)");
                return Ok(Vec::new());
            }
            s => {
                warn!("Shodan HTTP {s}");
                return Ok(Vec::new());
            }
        }

        let host = http.json::<Host>().await?;
        Ok(Self::to_observation(ioc, ty, host).into_iter().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host(ports: Vec<u16>, tags: Vec<&str>, vulns: Vec<&str>) -> Host {
        Host {
            ports,
            hostnames: vec!["mail.example.com".to_string()],
            tags: tags.into_iter().map(String::from).collect(),
            vulns: vulns.into_iter().map(String::from).collect(),
            org: Some("Example Org".to_string()),
            isp: None,
            asn: Some("AS64500".to_string()),
            os: None,
            country_name: Some("Netherlands".to_string()),
            last_update: Some("2026-07-10T00:00:00".to_string()),
        }
    }

    fn ioc() -> RawIoc {
        RawIoc::new("1.2.3.4".to_string())
    }

    #[test]
    fn exposure_alone_emits_no_observation() {
        let clean = host(vec![443, 22], vec!["cloud"], vec![]);
        assert!(Shodan::to_observation(&ioc(), &IndicatorType::IPv4, clean).is_none());
    }

    #[test]
    fn compromise_tag_beats_vuln_count() {
        assert_eq!(Shodan::confidence_for(0, true), 75);
        assert_eq!(Shodan::confidence_for(1, false), 35);
        assert_eq!(Shodan::confidence_for(7, false), 65);
        assert_eq!(Shodan::confidence_for(100, false), 65); // saturates
    }

    #[test]
    fn vulnerable_host_carries_exposure_context() {
        let h = host(
            vec![8080, 22],
            vec![],
            vec!["CVE-2024-3400", "CVE-2021-44228"],
        );
        let obs = Shodan::to_observation(&ioc(), &IndicatorType::IPv4, h).unwrap();
        assert_eq!(obs.confidence, 40);
        assert_eq!(
            obs.context.get("open_ports").map(String::as_str),
            Some("22,8080")
        );
        assert_eq!(
            obs.context.get("vulns").map(String::as_str),
            Some("CVE-2021-44228,CVE-2024-3400")
        );
        assert_eq!(
            obs.context.get("org").map(String::as_str),
            Some("Example Org")
        );
    }

    #[test]
    fn long_vuln_lists_are_truncated() {
        let cves: Vec<String> = (0..15).map(|i| format!("CVE-2024-{i:04}")).collect();
        let h = host(vec![80], vec![], cves.iter().map(String::as_str).collect());
        let obs = Shodan::to_observation(&ioc(), &IndicatorType::IPv4, h).unwrap();
        let vulns = obs.context.get("vulns").unwrap();
        assert!(vulns.ends_with("(+5 more)"));
    }

    #[test]
    fn compromised_tag_emits_even_without_vulns() {
        let h = host(vec![445], vec!["Compromised"], vec![]);
        let obs = Shodan::to_observation(&ioc(), &IndicatorType::IPv4, h).unwrap();
        assert_eq!(obs.confidence, 75);
        assert!(obs.tags.contains(&"Compromised".to_string()));
    }
}
