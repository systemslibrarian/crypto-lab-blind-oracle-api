# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Structured logging via `tracing` / `tracing-subscriber` (honors `RUST_LOG`).
- Graceful shutdown on `SIGTERM` / Ctrl-C, draining in-flight requests.
- Per-request timeout and a concurrency limit to bound CPU/memory under load.
- HTTP request tracing (`tower_http::trace`).
- End-to-end test suite that generates real TFHE keys and verifies homomorphic
  addition, overflow wrapping, server-key caching, and error handling.
- Continuous integration (`fmt`, `clippy -D warnings`, build, test, Docker build).
- `LICENSE` (MIT), `CONTRIBUTING.md`, `CHANGELOG.md`, `.editorconfig`, `rustfmt.toml`.
- Committed `Cargo.lock` for reproducible builds.
- `.dockerignore` and a HEALTHCHECK + non-root user in the Docker image.
- `healthCheckPath` in `render.yaml`.

### Changed
- Added the TFHE-rs 1.8.0 runtime with explicit per-request version selection,
  while retaining a TFHE-rs 0.8 compatibility path for already-open browser
  tabs. Raised the Rust/Docker toolchain floor to 1.91.1 and disabled 1.8's
  optional AVX-512 default for portable Render and Arm64 builds.
- The compute wire format now uses TFHE's versioned, size-limited safe
  serialization. Legacy raw-bincode requests remain accepted during the rolling
  browser upgrade, and responses preserve the request's format.
- Error responses now distinguish base64 / server-key / ciphertext failures
  instead of returning a single generic message.
- Dockerfile now caches the dependency build layer, runs as a non-root user, and
  pins a slim base image.
- Release profile uses thin LTO and a single codegen unit for faster FHE compute.

## [0.1.0]

### Added
- Initial blind-oracle API: `POST /compute/add` performs gate-bootstrapped
  homomorphic addition on two `FheUint8` ciphertexts using TFHE-rs, with a
  per-key server-key cache. The server never holds a `ClientKey`.
