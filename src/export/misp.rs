//! MISP export — a single MISP Event with one Attribute per indicator.

use crate::model::indicator::{Indicator, IndicatorType};
use anyhow::Result;
use serde_json::{json, Value};

pub fn render(indicators: &[Indicator]) -> Result<String> {
    let attributes: Vec<Value> = indicators
        .iter()
        .filter_map(|ind| misp_type(&ind.indicator_type).map(|(t, cat)| (ind, t, cat)))
        .map(|(ind, misp_type, category)| {
            json!({
                "type": misp_type,
                "category": category,
                "value": ind.value,
                "to_ids": ind.confidence >= 50,
                "comment": format!(
                    "sources: {}; confidence: {}",
                    ind.sources().join(", "),
                    ind.confidence
                ),
                "Tag": ind.tags.iter().map(|t| json!({ "name": t })).collect::<Vec<_>>(),
            })
        })
        .collect();

    let event = json!({
        "Event": {
            "info": "ThreatHarvester export",
            "Attribute": attributes,
        }
    });
    Ok(serde_json::to_string_pretty(&event)?)
}

/// Map an indicator type to a (MISP attribute type, MISP category) pair.
fn misp_type(ty: &IndicatorType) -> Option<(&'static str, &'static str)> {
    Some(match ty {
        IndicatorType::IPv4 | IndicatorType::IPv6 => ("ip-dst", "Network activity"),
        IndicatorType::Domain => ("domain", "Network activity"),
        IndicatorType::Url => ("url", "Network activity"),
        IndicatorType::Md5 => ("md5", "Payload delivery"),
        IndicatorType::Sha1 => ("sha1", "Payload delivery"),
        IndicatorType::Sha256 => ("sha256", "Payload delivery"),
        IndicatorType::Sha512 => ("sha512", "Payload delivery"),
        IndicatorType::Ssdeep => ("ssdeep", "Payload delivery"),
        IndicatorType::Email => ("email-src", "Payload delivery"),
        IndicatorType::Other(_) => return None,
    })
}
