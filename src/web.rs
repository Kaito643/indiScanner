//! Local web dashboard + REST API over the same engine the CLI uses.
//!
//! Binds to loopback only: the server holds API keys and reaches live-malware
//! sources, so it must never be exposed. Read-only by design — enrich, collect,
//! and a source listing; sample downloading is deliberately CLI/TUI-only.
//!
//! The single-page dashboard (embedded `web/index.html`) renders the
//! consensus-scored results as a table and draws each indicator's IOA layer —
//! relationship edges and ATT&CK techniques — as an interactive graph.

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::Html,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use threat_harvester::config::Config;
use threat_harvester::engine::Engine;
use threat_harvester::model::entity::ThreatEntity;
use threat_harvester::model::indicator::Indicator;
use threat_harvester::model::request::{Filters, RawIoc, Request};
use threat_harvester::sources::{self, ThreatSource};

#[derive(Clone)]
struct AppState {
    engine: Arc<Engine>,
    sources: Arc<Vec<SourceInfo>>,
}

/// Build the engine from config and serve the dashboard + API on `addr`.
pub async fn serve(config: Config, addr: SocketAddr) -> anyhow::Result<()> {
    let sources = Arc::new(source_info(&sources::from_config(&config)));
    let engine = Arc::new(Engine::new(sources::from_config(&config), config));
    let state = AppState { engine, sources };

    let app = Router::new()
        .route("/", get(|| async { Html(include_str!("web/index.html")) }))
        .route("/api/sources", get(list_sources))
        .route("/api/enrich", post(enrich))
        .route("/api/collect", get(collect))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    println!("ThreatHarvester dashboard on http://{addr}  (Ctrl-C to stop)");
    axum::serve(listener, app).await?;
    Ok(())
}

type ApiError = (StatusCode, String);

fn internal(e: impl std::fmt::Display) -> ApiError {
    (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
}

#[derive(Deserialize)]
struct EnrichBody {
    value: String,
}

async fn enrich(
    State(state): State<AppState>,
    Json(body): Json<EnrichBody>,
) -> Result<Json<Vec<Indicator>>, ApiError> {
    let value = body.value.trim();
    if value.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "value is required".to_string()));
    }
    let indicators = state
        .engine
        .run(Request::Enrich(RawIoc::new(value)))
        .await
        .map_err(internal)?;
    Ok(Json(indicators))
}

#[derive(Deserialize)]
struct CollectQuery {
    entity: String,
    kind: Option<String>,
    limit: Option<usize>,
}

async fn collect(
    State(state): State<AppState>,
    Query(q): Query<CollectQuery>,
) -> Result<Json<Vec<Indicator>>, ApiError> {
    if q.entity.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "entity is required".to_string()));
    }
    let request = Request::Collect {
        entity: ThreatEntity::new(
            q.entity,
            crate::parse_kind(q.kind.as_deref().unwrap_or("malware")),
        ),
        filters: Filters {
            max_results: q.limit,
            ..Filters::default()
        },
    };
    let indicators = state.engine.run(request).await.map_err(internal)?;
    Ok(Json(indicators))
}

async fn list_sources(State(state): State<AppState>) -> Json<Vec<SourceInfo>> {
    Json((*state.sources).clone())
}

#[derive(Clone, Serialize)]
struct SourceInfo {
    name: String,
    ioc_types: Vec<String>,
    operations: Vec<String>,
}

/// Snapshot the active sources' capabilities for the `/api/sources` endpoint.
fn source_info(active: &[Box<dyn ThreatSource>]) -> Vec<SourceInfo> {
    active
        .iter()
        .map(|s| {
            let caps = s.capabilities();
            SourceInfo {
                name: s.name().to_string(),
                ioc_types: caps
                    .ioc_types
                    .iter()
                    .map(|t| t.as_tag().to_string())
                    .collect(),
                operations: caps
                    .operations
                    .iter()
                    .map(|op| format!("{op:?}").to_lowercase())
                    .collect(),
            }
        })
        .collect()
}
