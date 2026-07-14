//! MITRE ATT&CK references — IOA groundwork.
//!
//! A stub for now. When IOA support lands, observations and indicators will be
//! able to carry `AttackPattern`s, letting the tool express behaviour (TTPs),
//! not just static artifacts.

use serde::{Deserialize, Serialize};

/// A reference to a MITRE ATT&CK technique.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackPattern {
    /// e.g. "T1059.001" (PowerShell).
    pub technique_id: String,
    /// Human-readable technique name, if known.
    pub name: Option<String>,
}
