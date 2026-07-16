//! Cross-cutting utilities: caching and per-source rate limiting.
//!
//! (Defang/refang currently lives in the `network` IOC-type module; it can move
//! here if other modules start needing it.)

pub mod cache;
pub mod http;
pub mod ratelimit;

pub use cache::Cache;
pub use http::{http_client, send_with_retry};
pub use ratelimit::RateLimiter;
