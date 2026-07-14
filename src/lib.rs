//! ThreatHarvester — a capability-routed Cyber Threat Intelligence aggregator.
//!
//! The crate is organized in layers (see the module docs for detail):
//!
//! - [`model`] — the lean domain model: `Observation` (raw per-source claim) and
//!   `Indicator` (merged + consensus-scored), plus threat entities and the
//!   relationship/attack stubs that IOA support will grow into.
//! - [`modules`] — IOC-*type* modules (network / file / email ...). Each owns
//!   validation, normalization, defanging and knows which sources are relevant
//!   for its type. This is the routing brain.
//! - [`sources`] — source *connectors*. Each declares a [`sources::Capability`]
//!   so the engine only calls sources that can answer a given request.
//! - [`engine`] — orchestration: route a [`Request`] to the right module, fan out
//!   to capable sources, aggregate observations into scored indicators.
//! - [`export`] — JSON / CSV / STIX 2.1 / MISP output adapters.
//! - [`util`] — caching and rate limiting.
//! - [`config`] — environment + config-file loading (aliases, keys, source toggles).

pub mod config;
pub mod engine;
pub mod export;
pub mod model;
pub mod modules;
pub mod sources;
pub mod util;

pub use model::request::Request;
