//! Relationships between indicators — IOA groundwork.
//!
//! Not populated yet. This is the seed of the relationship graph: modelling how
//! indicators connect (a domain resolves to an IP, a sample drops a payload) is
//! what makes Indicators of Attack (behavioural patterns over related indicators
//! + MITRE ATT&CK TTPs) a natural extension rather than a rewrite.

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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Relationship {
    pub source_value: String,
    pub target_value: String,
    pub kind: RelationKind,
}
