//! Relationships between indicators — the relationship-graph half of IOA.
//!
//! Sources attach edges to their observations (URLhaus: host `Hosts` each URL
//! it serves; MalwareBazaar: a sample's sibling hashes are `RelatedTo` its
//! SHA-256), and the aggregator unions them onto the merged indicator. Sandbox
//! sources will later add `Drops`/`CommunicatesWith` behaviour edges.

use serde::{Deserialize, Serialize};

/// How two indicators relate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RelationKind {
    /// Domain → IP address.
    ResolvesTo,
    /// Indicator communicates with a C2 endpoint.
    CommunicatesWith,
    /// Sample drops/downloads another artifact.
    Drops,
    /// Host serves a URL/sample.
    Hosts,
    /// Generic association.
    RelatedTo,
}

/// A directed edge between two indicator values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Relationship {
    pub source_value: String,
    pub target_value: String,
    pub kind: RelationKind,
}

impl Relationship {
    pub fn new(
        source_value: impl Into<String>,
        target_value: impl Into<String>,
        kind: RelationKind,
    ) -> Self {
        Self {
            source_value: source_value.into(),
            target_value: target_value.into(),
            kind,
        }
    }
}
