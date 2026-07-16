//! JSON export — the internal model serialized directly (full provenance).

use crate::model::indicator::Indicator;
use anyhow::Result;

pub fn render(indicators: &[Indicator]) -> Result<String> {
    Ok(serde_json::to_string_pretty(indicators)?)
}
