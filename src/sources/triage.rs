//! Recorded Future Triage (tria.ge) — sandbox behaviour for file hashes.
//!
//! This is the first *behavioural* source: beyond a verdict, a Triage report
//! carries what the sample **did** — network endpoints it contacted
//! (`CommunicatesWith` edges), its sibling digests (`RelatedTo` edges), and
//! ATT&CK techniques asserted by detonation signatures (attached directly to
//! the observation, not derived from tags).
//!
//! `lookup` finds the newest reported analysis of a hash and reads its
//! overview. `search` lists samples by family; those results carry no score,
//! so they map to a fixed mid-high confidence. Score mapping follows Triage's
//! own bands: 8-10 malicious (confidence = score × 10), 6-7 likely malicious
//! (45), below that no observation — sandbox noise is not a verdict.
//!
//! Network IOC edges are factual "the sample contacted this endpoint" claims;
//! they include benign infrastructure (OS telemetry, CRL checks) by design.

use super::{Capability, Operation, ThreatSource};
use crate::model::attack::AttackPattern;
use crate::model::entity::ThreatEntity;
use crate::model::indicator::{IndicatorType, Observation};
use crate::model::relationship::{RelationKind, Relationship};
use crate::model::request::{Filters, RawIoc};
use crate::util::{http_client, send_with_retry};
use anyhow::Result;
use async_trait::async_trait;
use log::{debug, warn};
use reqwest::Client;
use serde::Deserialize;
use std::env;

const API: &str = "https://tria.ge/api/v0";

/// Family search results carry no per-sample score; a Triage family
/// attribution is a strong signal short of a scored detonation.
const SEARCH_CONFIDENCE: u8 = 70;

/// The search endpoint serves at most 200 results per request.
const SEARCH_API_MAX: usize = 200;

pub struct Triage {
    client: Client,
    api_key: String,
}

impl Triage {
    /// Build from `TRIAGE_API_KEY`; returns `None` if the key is absent/empty.
    pub fn from_env() -> Option<Self> {
        let api_key = env::var("TRIAGE_API_KEY").ok().filter(|k| !k.is_empty())?;
        Some(Self {
            client: http_client(),
            api_key,
        })
    }

    async fn get_json<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<Option<T>> {
        let http = send_with_retry(
            self.client
                .get(format!("{API}/{path}"))
                .bearer_auth(&self.api_key),
        )
        .await?;
        match http.status() {
            s if s.is_success() => Ok(Some(http.json::<T>().await?)),
            reqwest::StatusCode::NOT_FOUND => Ok(None),
            reqwest::StatusCode::UNAUTHORIZED => {
                warn!("Triage unauthorized — check TRIAGE_API_KEY");
                Ok(None)
            }
            reqwest::StatusCode::TOO_MANY_REQUESTS => {
                warn!("Triage rate limit exceeded");
                Ok(None)
            }
            s => {
                warn!("Triage HTTP {s}");
                Ok(None)
            }
        }
    }

    /// Triage's 1-10 score → confidence, following its documented bands.
    fn confidence_for(score: u8) -> Option<u8> {
        match score {
            8..=10 => Some((score as u16 * 10).min(100) as u8),
            6..=7 => Some(45),
            _ => None,
        }
    }

    fn to_observation(ioc: &RawIoc, ty: &IndicatorType, overview: Overview) -> Option<Observation> {
        let confidence = Self::confidence_for(overview.analysis.score?)?;

        let mut obs = Observation::new(ioc.value.clone(), ty.clone(), "Triage", confidence);
        obs.first_seen = overview.sample.created.clone();
        obs.last_seen = overview.sample.completed.clone();
        obs.tags = overview.analysis.tags;
        if !overview.analysis.family.is_empty() {
            obs.context
                .insert("family".to_string(), overview.analysis.family.join(","));
        }
        obs.context.insert(
            "score".to_string(),
            overview.analysis.score.unwrap_or_default().to_string(),
        );
        if let Some(id) = &overview.sample.id {
            obs.context.insert("triage_id".to_string(), id.clone());
        }

        // Signature-asserted ATT&CK techniques — behaviour, not tag inference.
        for sig in &overview.signatures {
            for ttp in &sig.ttp {
                if !obs.attack_patterns.iter().any(|p| &p.technique_id == ttp) {
                    obs.attack_patterns.push(AttackPattern {
                        technique_id: ttp.clone(),
                        name: None,
                    });
                }
            }
        }

        // Graph edges hang off the sample's SHA-256 identity.
        if let Some(sha256) = &overview.sample.sha256 {
            for sibling in [&overview.sample.md5, &overview.sample.sha1]
                .into_iter()
                .flatten()
            {
                obs.relationships.push(Relationship::new(
                    sha256.clone(),
                    sibling.clone(),
                    RelationKind::RelatedTo,
                ));
            }
            for target in &overview.targets {
                let endpoints = target
                    .iocs
                    .domains
                    .iter()
                    .chain(&target.iocs.ips)
                    .chain(&target.iocs.urls);
                for endpoint in endpoints {
                    let edge = Relationship::new(
                        sha256.clone(),
                        endpoint.clone(),
                        RelationKind::CommunicatesWith,
                    );
                    if !obs.relationships.contains(&edge) {
                        obs.relationships.push(edge);
                    }
                }
            }
        }
        Some(obs)
    }
}

#[derive(Deserialize)]
struct SearchResponse {
    #[serde(default)]
    data: Vec<SearchHit>,
}

#[derive(Deserialize)]
struct SearchHit {
    id: String,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    sha256: Option<String>,
    #[serde(default)]
    submitted: Option<String>,
}

#[derive(Deserialize)]
struct Overview {
    sample: Sample,
    analysis: Analysis,
    #[serde(default)]
    signatures: Vec<Signature>,
    #[serde(default)]
    targets: Vec<Target>,
}

#[derive(Deserialize)]
struct Sample {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    sha256: Option<String>,
    #[serde(default)]
    sha1: Option<String>,
    #[serde(default)]
    md5: Option<String>,
    #[serde(default)]
    created: Option<String>,
    #[serde(default)]
    completed: Option<String>,
}

#[derive(Deserialize)]
struct Analysis {
    #[serde(default)]
    score: Option<u8>,
    #[serde(default)]
    family: Vec<String>,
    #[serde(default)]
    tags: Vec<String>,
}

#[derive(Deserialize)]
struct Signature {
    #[serde(default)]
    ttp: Vec<String>,
}

#[derive(Deserialize)]
struct Target {
    #[serde(default)]
    iocs: Iocs,
}

#[derive(Deserialize, Default)]
struct Iocs {
    #[serde(default)]
    domains: Vec<String>,
    #[serde(default)]
    ips: Vec<String>,
    #[serde(default)]
    urls: Vec<String>,
}

#[async_trait]
impl ThreatSource for Triage {
    fn name(&self) -> &str {
        "Triage"
    }

    fn capabilities(&self) -> Capability {
        Capability {
            ioc_types: vec![
                IndicatorType::Md5,
                IndicatorType::Sha1,
                IndicatorType::Sha256,
                IndicatorType::Sha512,
            ],
            operations: vec![Operation::Lookup, Operation::Search],
        }
    }

    async fn lookup(&self, ioc: &RawIoc, ty: &IndicatorType) -> Result<Vec<Observation>> {
        let tag = match ty {
            IndicatorType::Md5 => "md5",
            IndicatorType::Sha1 => "sha1",
            IndicatorType::Sha256 => "sha256",
            IndicatorType::Sha512 => "sha512",
            _ => return Ok(Vec::new()),
        };
        debug!("Triage search {tag}:{}", ioc.value);
        let Some(search) = self
            .get_json::<SearchResponse>(&format!("search?query={tag}:{}&limit=5", ioc.value))
            .await?
        else {
            return Ok(Vec::new());
        };
        // Newest reported analysis wins (results are newest-first).
        let Some(hit) = search
            .data
            .iter()
            .find(|h| h.status.as_deref() == Some("reported"))
        else {
            debug!("Triage: no reported analysis for {}", ioc.value);
            return Ok(Vec::new());
        };

        let Some(overview) = self
            .get_json::<Overview>(&format!("samples/{}/overview.json", hit.id))
            .await?
        else {
            return Ok(Vec::new());
        };
        Ok(Self::to_observation(ioc, ty, overview)
            .into_iter()
            .collect())
    }

    async fn search(&self, entity: &ThreatEntity, filters: &Filters) -> Result<Vec<Observation>> {
        let cap = super::search_cap(filters, SEARCH_API_MAX);
        let family = entity.name.to_lowercase();
        debug!("Triage family search: {family} (limit {cap})");
        let Some(search) = self
            .get_json::<SearchResponse>(&format!("search?query=family:{family}&limit={cap}"))
            .await?
        else {
            return Ok(Vec::new());
        };

        let mut out = Vec::new();
        for hit in &search.data {
            // Search rows carry no score/behaviour; a full overview per row
            // would be one API call each. Emit lightweight observations.
            let Some(sha256) = &hit.sha256 else { continue };
            if out
                .iter()
                .any(|o: &Observation| &o.value == sha256 && o.source == "Triage")
            {
                continue; // resubmissions of the same sample
            }
            let mut obs = Observation::new(
                sha256.clone(),
                IndicatorType::Sha256,
                "Triage",
                SEARCH_CONFIDENCE,
            );
            obs.first_seen = hit.submitted.clone();
            obs.tags.push(format!("family:{family}"));
            obs.context.insert("triage_id".to_string(), hit.id.clone());
            out.push(obs);
        }
        super::warn_if_capped("Triage", search.data.len(), cap);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn overview(score: Option<u8>) -> Overview {
        Overview {
            sample: Sample {
                id: Some("260716-abc".to_string()),
                sha256: Some("a".repeat(64)),
                sha1: Some("b".repeat(40)),
                md5: Some("c".repeat(32)),
                created: Some("2026-07-16T02:20:34Z".to_string()),
                completed: Some("2026-07-16T02:28:38Z".to_string()),
            },
            analysis: Analysis {
                score,
                family: vec!["lockbit".to_string()],
                tags: vec!["family:lockbit".to_string(), "ransomware".to_string()],
            },
            signatures: vec![
                Signature {
                    ttp: vec!["T1486".to_string(), "T1490".to_string()],
                },
                Signature {
                    ttp: vec!["T1486".to_string()], // duplicate across signatures
                },
            ],
            targets: vec![Target {
                iocs: Iocs {
                    domains: vec!["evil.example".to_string()],
                    ips: vec!["1.2.3.4".to_string()],
                    urls: vec![],
                },
            }],
        }
    }

    fn ioc() -> RawIoc {
        RawIoc::new("a".repeat(64))
    }

    #[test]
    fn score_bands_follow_triage_semantics() {
        assert_eq!(Triage::confidence_for(10), Some(100));
        assert_eq!(Triage::confidence_for(8), Some(80));
        assert_eq!(Triage::confidence_for(7), Some(45));
        assert_eq!(Triage::confidence_for(6), Some(45));
        assert_eq!(Triage::confidence_for(5), None);
        assert_eq!(Triage::confidence_for(1), None);
    }

    #[test]
    fn low_score_emits_no_observation() {
        assert!(
            Triage::to_observation(&ioc(), &IndicatorType::Sha256, overview(Some(3))).is_none()
        );
        assert!(Triage::to_observation(&ioc(), &IndicatorType::Sha256, overview(None)).is_none());
    }

    #[test]
    fn observation_carries_ttps_deduplicated() {
        let obs =
            Triage::to_observation(&ioc(), &IndicatorType::Sha256, overview(Some(10))).unwrap();
        let ids: Vec<&str> = obs
            .attack_patterns
            .iter()
            .map(|p| p.technique_id.as_str())
            .collect();
        assert_eq!(ids, vec!["T1486", "T1490"]);
    }

    #[test]
    fn observation_carries_sibling_and_network_edges() {
        let obs =
            Triage::to_observation(&ioc(), &IndicatorType::Sha256, overview(Some(9))).unwrap();
        assert_eq!(obs.confidence, 90);
        let kinds: Vec<RelationKind> = obs.relationships.iter().map(|r| r.kind).collect();
        assert_eq!(
            kinds,
            vec![
                RelationKind::RelatedTo,        // sha256 -> md5
                RelationKind::RelatedTo,        // sha256 -> sha1
                RelationKind::CommunicatesWith, // domain
                RelationKind::CommunicatesWith, // ip
            ]
        );
        assert!(obs
            .relationships
            .iter()
            .any(|r| r.target_value == "evil.example"));
        assert_eq!(
            obs.context.get("family").map(String::as_str),
            Some("lockbit")
        );
    }
}
