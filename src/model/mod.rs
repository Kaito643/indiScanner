//! The lean domain model.
//!
//! The central refinement over the v1 engine is the split between an
//! [`indicator::Observation`] (one source's raw claim about a value, carrying
//! provenance) and an [`indicator::Indicator`] (the merged, deduplicated,
//! consensus-scored result).

pub mod attack;
pub mod entity;
pub mod indicator;
pub mod relationship;
pub mod request;

pub use entity::{EntityKind, ThreatEntity};
pub use indicator::{Indicator, IndicatorType, Observation};
pub use request::{Filters, RawIoc, Request};
