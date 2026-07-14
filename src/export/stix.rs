//! STIX 2.1 export — a `bundle` of `indicator` SDOs.
//!
//! IDs are deterministic (UUIDv5 over the pattern) so the same IOC yields the
//! same STIX id across runs, which keeps downstream de-duplication stable.

use crate::model::indicator::{Indicator, IndicatorType};
use anyhow::Result;
use serde_json::{json, Value};
use uuid::Uuid;

/// Fixed namespace for ThreatHarvester-generated STIX ids.
const NAMESPACE: Uuid = Uuid::from_bytes([
    0x54, 0x48, 0x52, 0x54, 0x48, 0x41, 0x52, 0x56, 0x45, 0x53, 0x54, 0x45, 0x52, 0x53, 0x54, 0x49,
]);

pub fn render(indicators: &[Indicator]) -> Result<String> {
    let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);

    let objects: Vec<Value> = indicators
        .iter()
        .filter_map(|ind| pattern_for(&ind.indicator_type, &ind.value).map(|p| (ind, p)))
        .map(|(ind, pattern)| {
            let id = Uuid::new_v5(&NAMESPACE, pattern.as_bytes());
            let valid_from = ind
                .observations
                .iter()
                .find_map(|o| o.first_seen.clone())
                .unwrap_or_else(|| now.clone());

            json!({
                "type": "indicator",
                "spec_version": "2.1",
                "id": format!("indicator--{id}"),
                "created": now,
                "modified": now,
                "name": ind.value,
                "pattern": pattern,
                "pattern_type": "stix",
                "valid_from": valid_from,
                "confidence": ind.confidence,
                "labels": ind.tags,
                "x_sources": ind.sources(),
            })
        })
        .collect();

    let bundle_id = Uuid::new_v5(&NAMESPACE, now.as_bytes());
    let bundle = json!({
        "type": "bundle",
        "id": format!("bundle--{bundle_id}"),
        "objects": objects,
    });
    Ok(serde_json::to_string_pretty(&bundle)?)
}

/// Build a STIX pattern for a value, or `None` for types STIX can't express here.
fn pattern_for(ty: &IndicatorType, value: &str) -> Option<String> {
    let v = value.replace('\'', "\\'");
    Some(match ty {
        IndicatorType::IPv4 => format!("[ipv4-addr:value = '{v}']"),
        IndicatorType::IPv6 => format!("[ipv6-addr:value = '{v}']"),
        IndicatorType::Domain => format!("[domain-name:value = '{v}']"),
        IndicatorType::Url => format!("[url:value = '{v}']"),
        IndicatorType::Md5 => format!("[file:hashes.'MD5' = '{v}']"),
        IndicatorType::Sha1 => format!("[file:hashes.'SHA-1' = '{v}']"),
        IndicatorType::Sha256 => format!("[file:hashes.'SHA-256' = '{v}']"),
        IndicatorType::Email => format!("[email-addr:value = '{v}']"),
        IndicatorType::Other(_) => return None,
    })
}
