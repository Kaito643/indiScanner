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
#[derive(Debug, Clone, Default)]
pub struct Filters {
    /// Look back this many days (`None` = use each source's default).
    pub lookback_days: Option<u32>,
}
