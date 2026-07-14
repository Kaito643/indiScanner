//! URLhaus (abuse.ch) — malicious URLs. `lookup` by URL or host, `search` by tag.

use super::{Capability, Operation, ThreatSource};
use crate::model::entity::ThreatEntity;
use crate::model::indicator::{IndicatorType, Observation};
use crate::model::request::RawIoc;
use anyhow::Result;
use async_trait::async_trait;
use log::{debug, warn};
use reqwest::Client;
use serde::Deserialize;

const TAG_API: &str = "https://urlhaus-api.abuse.ch/v1/tag/";
const URL_API: &str = "https://urlhaus-api.abuse.ch/v1/url/";
const HOST_API: &str = "https://urlhaus-api.abuse.ch/v1/host/";

/// URLhaus has no per-entry confidence score; a listed URL is treated as high.
const LISTED_CONFIDENCE: u8 = 90;

pub struct URLhaus {
    client: Client,
    auth_key: Option<String>,
}

impl Default for URLhaus {
    fn default() -> Self {
        Self::new()
    }
}

impl URLhaus {
    pub fn new() -> Self {
        Self {
            client: Client::new(),
            auth_key: super::abuse_ch_key(),
        }
    }

    fn to_observation(u: UrlEntry) -> Observation {
        let mut obs = Observation::new(u.url, IndicatorType::Url, "URLhaus", LISTED_CONFIDENCE);
        obs.first_seen = u.date_added;
        obs.tags = u.tags.unwrap_or_default();
        if let Some(t) = u.threat {
            obs.context.insert("threat".to_string(), t);
        }
        if let Some(s) = u.url_status {
            obs.context.insert("url_status".to_string(), s);
        }
        obs
    }

    /// Attach the abuse.ch `Auth-Key` header when configured.
    fn authed(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.auth_key {
            Some(key) => req.header("Auth-Key", key),
            None => req,
        }
    }

    async fn post_urls(&self, url: &str, form: &[(&str, &str)]) -> Result<Vec<Observation>> {
        let http = self.authed(self.client.post(url).form(form)).send().await?;
        if !http.status().is_success() {
            warn!(
                "URLhaus HTTP {}: {}",
                http.status(),
                super::auth_hint(http.status())
            );
            return Ok(Vec::new());
        }
        let resp: UrlsResponse = http.json().await?;

        if resp.query_status != "ok" {
            if !matches!(resp.query_status.as_str(), "no_results" | "no_result") {
                warn!("URLhaus status: {}", resp.query_status);
            }
            return Ok(Vec::new());
        }
        Ok(resp
            .urls
            .unwrap_or_default()
            .into_iter()
            .map(Self::to_observation)
            .collect())
    }
}

#[derive(Deserialize)]
struct UrlsResponse {
    query_status: String,
    urls: Option<Vec<UrlEntry>>,
}

/// Response for a single-URL lookup (fields sit at the top level, not under `urls`).
#[derive(Deserialize)]
struct SingleUrlResponse {
    query_status: String,
    #[serde(flatten)]
    entry: Option<UrlEntry>,
}

#[derive(Deserialize)]
struct UrlEntry {
    url: String,
    #[serde(default)]
    date_added: Option<String>,
    #[serde(default)]
    tags: Option<Vec<String>>,
    #[serde(default)]
    threat: Option<String>,
    #[serde(default)]
    url_status: Option<String>,
}

#[async_trait]
impl ThreatSource for URLhaus {
    fn name(&self) -> &str {
        "URLhaus"
    }

    fn capabilities(&self) -> Capability {
        Capability {
            ioc_types: vec![
                IndicatorType::Url,
                IndicatorType::Domain,
                IndicatorType::IPv4,
                IndicatorType::IPv6,
            ],
            operations: vec![Operation::Lookup, Operation::Search],
        }
    }

    async fn lookup(&self, ioc: &RawIoc, ty: &IndicatorType) -> Result<Vec<Observation>> {
        match ty {
            IndicatorType::Url => {
                debug!("URLhaus url lookup: {}", ioc.value);
                let http = self
                    .authed(
                        self.client
                            .post(URL_API)
                            .form(&[("url", ioc.value.as_str())]),
                    )
                    .send()
                    .await?;
                if !http.status().is_success() {
                    warn!(
                        "URLhaus HTTP {}: {}",
                        http.status(),
                        super::auth_hint(http.status())
                    );
                    return Ok(Vec::new());
                }
                let resp: SingleUrlResponse = http.json().await?;
                if resp.query_status != "ok" {
                    return Ok(Vec::new());
                }
                Ok(resp.entry.map(Self::to_observation).into_iter().collect())
            }
            _ => {
                debug!("URLhaus host lookup: {}", ioc.value);
                self.post_urls(HOST_API, &[("host", ioc.value.as_str())])
                    .await
            }
        }
    }

    async fn search(&self, entity: &ThreatEntity) -> Result<Vec<Observation>> {
        debug!("URLhaus tag search: {}", entity.name);
        self.post_urls(TAG_API, &[("tag", entity.name.as_str())])
            .await
    }
}
