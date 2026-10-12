//! FHE context for TFHE-rs.
//!
//! The server does **not** generate keys. It receives the `ServerKey` from the
//! client on each compute request (or retrieves it from cache) and registers it
//! in the matching TFHE 0.8 or 1.8 thread-local runtime before computation.
//!
//! TFHE-rs requires no server-side initialization beyond registering the server
//! key per request. This context exists only to confirm the library is linked
//! and available before the server begins accepting traffic.

pub struct FheContext {
    pub ready: bool,
}

pub fn init() -> FheContext {
    tracing::info!("TFHE-rs 0.8 compatibility and 1.8 native bindings ready");
    tracing::info!("scheme: TFHE with gate bootstrapping");
    tracing::info!("ServerKey: received per-request from client");
    tracing::info!("ClientKey: never held by this server");
    FheContext { ready: true }
}
