//! HTTP plumbing shared by all sources: a client with a request timeout, and
//! send-with-retry on transient failures (5xx, timeout, connection errors).
//!
//! Retries happen inside a single router dispatch, after the per-source rate
//! limiter has been acquired — the short backoff (0.5s, then 1.5s) stays well
//! under any source's pacing except VirusTotal's, where a retried request may
//! arrive early once; VT answers that with a 429, which is not retried.

use log::warn;
use reqwest::{Client, RequestBuilder, Response};
use std::time::Duration;

/// Total attempts: one initial try plus up to two retries.
const ATTEMPTS: u32 = 3;
const FIRST_BACKOFF: Duration = Duration::from_millis(500);

/// A client for source connectors: 30s total per request, so one hung source
/// can't stall a whole fan-out indefinitely.
pub fn http_client() -> Client {
    Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .expect("TLS backend available")
}

/// Send a request, retrying transient failures with exponential backoff.
///
/// Retried: any 5xx response, timeouts, connection errors. Everything else
/// (2xx-4xx, redirect loops, decode errors) is returned as-is on first answer.
pub async fn send_with_retry(request: RequestBuilder) -> reqwest::Result<Response> {
    let mut backoff = FIRST_BACKOFF;
    for attempt in 1..ATTEMPTS {
        // Streaming bodies can't be cloned; fall through to the single try.
        let Some(clone) = request.try_clone() else {
            break;
        };
        match clone.send().await {
            Ok(resp) if resp.status().is_server_error() => {
                warn!(
                    "HTTP {} from {}; retry {attempt}/{}",
                    resp.status(),
                    resp.url(),
                    ATTEMPTS - 1
                );
            }
            Err(e) if e.is_timeout() || e.is_connect() => {
                warn!(
                    "transient transport error; retry {attempt}/{}: {e}",
                    ATTEMPTS - 1
                );
            }
            other => return other,
        }
        tokio::time::sleep(backoff).await;
        backoff *= 3;
    }
    request.send().await
}
