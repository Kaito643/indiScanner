use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IndicatorType {
    IPv4,
    IPv6,
    Domain,
    URL,
    SHA256,
    MD5,
    Other(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ThreatEntity {
    Actor,
    MalwareFamily,
    Campaign,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Indicator {
    pub value: String,
    pub indicator_type: IndicatorType,
    pub source: String,
    pub first_seen: Option<String>,
    pub confidence_level: u8,
    pub tags: Vec<String>,
}

impl fmt::Display for Indicator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {} ({})", self.source, self.value, self.confidence_level)
    }
}

pub struct QueryConfig {
    pub target_name: String,
    pub target_type: ThreatEntity,
    pub lookback_days: u32,
}
