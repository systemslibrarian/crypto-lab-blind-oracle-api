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

use routes::compute::{compute_add, AppState, BOOTSTRAPPING_MODE};

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
        "bootstrapping": BOOTSTRAPPING_MODE,
        "expectedComputeMs": "100-2000",
        "serverKeyDeserializeMs": "1000-5000 (cached after first use)",
        "gitCommit": env!("GIT_COMMIT"),
        "builtAt": env!("BUILT_AT")
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    // `/health` is the cheap endpoint the browser client and the deploy health
    // check both poll, and it carries the bootstrapping label. Gate
    // bootstrapping is TFHE's boolean API; this service uses the integer API,
    // where every `FheUint8` block operation runs a programmable bootstrap.
    // This test fails if the value reverts or the key is renamed.
    #[tokio::test]
    async fn health_reports_programmable_bootstrapping() {
        let axum::Json(body) = health().await;

        assert_eq!(
            body.get("bootstrapping").and_then(|v| v.as_str()),
            Some("programmable_bootstrapping_per_operation"),
            "health body was {body}"
        );
    }

    // The point of these two fields is to tie a live response to the exact
    // commit that produced the binary, so a placeholder is a failure, not a
    // degraded success. `build.rs` refuses to emit one, and this test is the
    // second line of defence: it fails if the SHA is absent, empty, short,
    // non-hex, or a word like "unknown".
    #[tokio::test]
    async fn health_reports_the_build_commit_and_build_time() {
        let axum::Json(body) = health().await;

        let commit = body
            .get("gitCommit")
            .and_then(|v| v.as_str())
            .unwrap_or_else(|| panic!("health body has no gitCommit string: {body}"));

        assert_eq!(
            commit.len(),
            40,
            "gitCommit must be a full 40-character SHA, got {commit:?}"
        );
        assert!(
            commit.bytes().all(|b| b.is_ascii_hexdigit()),
            "gitCommit must be hex, got {commit:?}"
        );

        let built_at = body
            .get("builtAt")
            .and_then(|v| v.as_str())
            .unwrap_or_else(|| panic!("health body has no builtAt string: {body}"));

        let parsed = parse_rfc3339_utc(built_at)
            .unwrap_or_else(|| panic!("builtAt {built_at:?} is not RFC 3339 UTC"));

        // Guards against a zeroed or epoch-defaulted stamp.
        assert!(
            parsed.0 >= 2026,
            "builtAt {built_at:?} predates this change"
        );
    }

    /// Strict `YYYY-MM-DDTHH:MM:SSZ` parser, returning the field values so the
    /// caller can range-check them. Deliberately rejects offsets other than
    /// `Z`, since the field is documented as UTC.
    fn parse_rfc3339_utc(value: &str) -> Option<(u32, u32, u32, u32, u32, u32)> {
        let bytes = value.as_bytes();
        if bytes.len() != 20 {
            return None;
        }
        for (index, expected) in [(4, b'-'), (7, b'-'), (10, b'T'), (13, b':'), (16, b':')] {
            if bytes[index] != expected {
                return None;
            }
        }
        if bytes[19] != b'Z' {
            return None;
        }

        let field = |range: std::ops::Range<usize>| value.get(range)?.parse::<u32>().ok();
        let year = field(0..4)?;
        let month = field(5..7)?;
        let day = field(8..10)?;
        let hour = field(11..13)?;
        let minute = field(14..16)?;
        let second = field(17..19)?;

        let valid = (1..=12).contains(&month)
            && (1..=31).contains(&day)
            && hour < 24
            && minute < 60
            && second < 60;

        valid.then_some((year, month, day, hour, minute, second))
    }
}
