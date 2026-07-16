//! The unified request type. One engine serves both verbs.

use super::entity::ThreatEntity;

/// A single unit of work for the engine.
#[derive(Debug, Clone)]
pub enum Request {
    /// Enrich a single IOC value — its type is auto-detected by the IOC-type
    /// modules, then every capable source is queried for reputation/context.
    Enrich(RawIoc),

    /// Collect IOCs related to a threat entity (actor / malware family / campaign).
    Collect {
        entity: ThreatEntity,
        filters: Filters,
    },
}

/// A raw, not-yet-typed IOC value supplied by the user (may be defanged).
#[derive(Debug, Clone)]
pub struct RawIoc {
    pub value: String,
}

impl RawIoc {
    pub fn new(value: impl Into<String>) -> Self {
        Self {
            value: value.into(),
        }
    }
}

/// Optional constraints applied to a `Collect` request.
///
/// `max_results` / `lookback_days` bound the *source queries*; `tag`,
/// `ioc_type`, and `min_confidence` filter the *aggregated indicators* after
/// consensus scoring.
#[derive(Debug, Clone, Default)]
pub struct Filters {
    /// Look back this many days (`None` = use each source's default).
    pub lookback_days: Option<u32>,
    /// Cap results per source (`None` = each source's API maximum). Sources
    /// log a warning when a response hits the cap, so truncation is never silent.
    pub max_results: Option<usize>,
    /// Keep only indicators with a tag containing this substring (case-insensitive).
    pub tag: Option<String>,
    /// Keep only indicators of this type tag (e.g. `sha256`, `ipv4`, `url`).
    pub ioc_type: Option<String>,
    /// Keep only indicators whose consensus confidence is at least this.
    pub min_confidence: Option<u8>,
}

impl Filters {
    /// Does this indicator pass the result filters (tag / type / confidence)?
    pub fn keeps(&self, ind: &crate::model::indicator::Indicator) -> bool {
        if let Some(min) = self.min_confidence {
            if ind.confidence < min {
                return false;
            }
        }
        if let Some(ty) = &self.ioc_type {
            if !ind.indicator_type.as_tag().eq_ignore_ascii_case(ty) {
                return false;
            }
        }
        if let Some(tag) = &self.tag {
            let needle = tag.to_lowercase();
            if !ind.tags.iter().any(|t| t.to_lowercase().contains(&needle)) {
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::indicator::{Indicator, IndicatorType};

    fn ind(ty: IndicatorType, conf: u8, tags: &[&str]) -> Indicator {
        Indicator {
            value: "v".into(),
            indicator_type: ty,
            confidence: conf,
            tags: tags.iter().map(|s| s.to_string()).collect(),
            attack_patterns: Vec::new(),
            relationships: Vec::new(),
            observations: Vec::new(),
        }
    }

    #[test]
    fn empty_filters_keep_everything() {
        let f = Filters::default();
        assert!(f.keeps(&ind(IndicatorType::Url, 10, &[])));
    }

    #[test]
    fn type_and_confidence_and_tag_all_apply() {
        let f = Filters {
            ioc_type: Some("sha256".into()),
            min_confidence: Some(80),
            tag: Some("ransomware".into()),
            ..Default::default()
        };
        assert!(f.keeps(&ind(IndicatorType::Sha256, 90, &["LockBit ransomware"])));
        assert!(!f.keeps(&ind(IndicatorType::Sha256, 90, &["trojan"]))); // wrong tag
        assert!(!f.keeps(&ind(IndicatorType::Sha256, 70, &["ransomware"]))); // too low
        assert!(!f.keeps(&ind(IndicatorType::Url, 90, &["ransomware"]))); // wrong type
    }
}
