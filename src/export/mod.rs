//! Output adapters: JSON, CSV, STIX 2.1, and MISP.
//!
//! The lean internal model maps cleanly onto STIX Cyber-observable / Indicator
//! SDOs and MISP attributes, so these adapters stay thin.

mod csv;
mod json;
mod misp;
mod stix;

use crate::model::indicator::Indicator;
use anyhow::Result;
use std::str::FromStr;

/// Supported output formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Json,
    Csv,
    Stix,
    Misp,
}

impl FromStr for Format {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "json" => Ok(Format::Json),
            "csv" => Ok(Format::Csv),
            "stix" | "stix2" | "stix2.1" => Ok(Format::Stix),
            "misp" => Ok(Format::Misp),
            other => anyhow::bail!("unknown output format '{other}' (json|csv|stix|misp)"),
        }
    }
}

/// Render indicators in the requested format.
pub fn render(indicators: &[Indicator], format: Format) -> Result<String> {
    match format {
        Format::Json => json::render(indicators),
        Format::Csv => Ok(csv::render(indicators)),
        Format::Stix => stix::render(indicators),
        Format::Misp => misp::render(indicators),
    }
}
