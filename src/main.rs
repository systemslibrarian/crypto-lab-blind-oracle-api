mod fhe;
mod routes;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::DefaultBodyLimit;
use axum::http::{header, HeaderValue, Method};
use axum::routing::{get, post};
use axum::Router;
use tower::limit::ConcurrencyLimitLayer;
use tower::ServiceBuilder;
use tower_http::cors::CorsLayer;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use routes::compute::{compute_add, AppState};

/// Maximum request body size. An FHE `ServerKey` plus two ciphertexts can be
/// tens of megabytes, so the limit is generous but bounded to prevent abuse.
const MAX_BODY_BYTES: usize = 100 * 1024 * 1024; // 100 MB

/// Hard ceiling on how long a single request may run. A legitimate request
/// (server-key deserialization + bootstrapped addition) completes well within
/// this; the timeout exists to shed stuck or malicious requests.
const REQUEST_TIMEOUT_SECS: u64 = 60;

/// Default listen port, overridable via the `PORT` environment variable.
const DEFAULT_PORT: u16 = 3001;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing();

    // Confirm the TFHE-rs context is available before accepting traffic.
    let ctx = fhe::init();
    if !ctx.ready {
        tracing::error!("failed to initialize TFHE-rs context");
        std::process::exit(1);
    }

    let state = Arc::new(AppState::new());

    // FHE server keys are large and computation is CPU-bound. Bound concurrency
    // to the available parallelism so a burst of requests cannot exhaust memory.
    let max_concurrency = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);
    tracing::info!(max_concurrency, "concurrency limit set");

    let cors = CorsLayer::new()
        .allow_origin([
            "https://systemslibrarian.github.io".parse::<HeaderValue>()?,
            "http://localhost:5173".parse::<HeaderValue>()?,
        ])
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers([header::CONTENT_TYPE]);

    let middleware = ServiceBuilder::new()
        .layer(TraceLayer::new_for_http())
        .layer(cors)
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .layer(TimeoutLayer::new(Duration::from_secs(REQUEST_TIMEOUT_SECS)))
        .layer(ConcurrencyLimitLayer::new(max_concurrency));

    let app = Router::new()
        .route("/", get(index))
        .route("/health", get(health))
        .route("/compute/add", post(compute_add))
        .layer(middleware)
        .with_state(state);

    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(DEFAULT_PORT);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "blind-oracle-api listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    tracing::info!("server shut down cleanly");
    Ok(())
}

/// Initialize structured logging. Honors the `RUST_LOG` environment variable
/// (e.g. `RUST_LOG=debug`); defaults to `info` for this crate and tower-http.
fn init_tracing() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("blind_oracle_api=info,tower_http=info,axum=info"));
    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer())
        .init();
}

/// Resolves when the process receives Ctrl-C or (on Unix) SIGTERM, allowing
/// in-flight requests to finish before exit. SIGTERM is what container
/// orchestrators (Render, Docker, Kubernetes) send on shutdown.
async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl-C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    tracing::info!("shutdown signal received; draining in-flight requests");
}

/// Service discovery root. Lists available routes and methods.
async fn index() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({
        "service": "blind-oracle-api",
        "status": "ok",
        "description": "Blind FHE oracle over TFHE-rs. The server computes on ciphertexts it cannot decrypt.",
        "routes": {
            "health": { "method": "GET", "path": "/health" },
            "computeAdd": { "method": "POST", "path": "/compute/add" }
        }
    }))
}

/// Liveness/readiness probe. Cheap and side-effect free.
async fn health() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({
        "status": "ok",
        "scheme": "TFHE-rs",
        "fhe": true,
        "tfheVersions": ["0.8", "1.8"],
        "bootstrapping": "gate_bootstrapping_per_operation",
        "expectedComputeMs": "100-2000",
        "serverKeyDeserializeMs": "1000-5000 (cached after first use)"
    }))
}
