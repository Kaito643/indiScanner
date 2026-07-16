//! Threat entities — the subject of a `Collect` request.

use serde::{Deserialize, Serialize};

/// What kind of thing we are collecting IOCs for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EntityKind {
    Actor,
    MalwareFamily,
    Campaign,
}

/// A named threat entity (e.g. actor "Lazarus", malware family "LockBit").
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatEntity {
    pub name: String,
    pub kind: EntityKind,
}

impl ThreatEntity {
    pub fn new(name: impl Into<String>, kind: EntityKind) -> Self {
        Self {
            name: name.into(),
            kind,
        }
    }
}
