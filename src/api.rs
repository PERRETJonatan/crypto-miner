//! Local HTTP API exposing miner status. This is the hook the monitoring
//! platform will use to collect data from each node.

use crate::stats::Stats;
use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::info;

pub async fn serve(addr: SocketAddr, stats: Arc<Stats>) -> anyhow::Result<()> {
    let app = Router::new()
        .route("/api/v1/health", get(|| async { "ok" }))
        .route("/api/v1/status", get(status))
        .with_state(stats);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!("status API listening on http://{addr}/api/v1/status");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn status(State(stats): State<Arc<Stats>>) -> Json<crate::stats::Snapshot> {
    Json(stats.snapshot())
}
