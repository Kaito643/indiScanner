//! Cross-cutting utilities: caching and per-source rate limiting.
//!
//! (Defang/refang currently lives in the `network` IOC-type module; it can move
//! here if other modules start needing it.)

pub mod cache;
pub mod ratelimit;

pub use cache::Cache;
pub use ratelimit::RateLimiter;
