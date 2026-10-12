# syntax=docker/dockerfile:1

# ---- Build stage ------------------------------------------------------------
FROM rust:1.91.1-slim-bookworm AS builder
WORKDIR /app

# Pre-build dependencies as a cacheable layer. TFHE-rs is large (5-10 min on a
# cold build), so we compile the dependency graph against a stub binary first;
# this layer is only invalidated when Cargo.toml / Cargo.lock change.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src \
    && echo 'fn main() {}' > src/main.rs \
    && cargo build --release \
    && rm -rf src

# Now build the real sources. Only our crate recompiles on source changes.
COPY . .
RUN touch src/main.rs && cargo build --release

# ---- Runtime stage ----------------------------------------------------------
FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 appuser

WORKDIR /app
COPY --from=builder /app/target/release/blind-oracle-api .

USER appuser
ENV PORT=3001
EXPOSE 3001

# Self-contained liveness check (Render also probes /health independently).
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -fsS "http://localhost:${PORT}/health" || exit 1

CMD ["./blind-oracle-api"]
