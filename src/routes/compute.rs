use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::{Arc, Mutex};
use std::time::Instant;
#[allow(unused_imports)]
use tfhe_08::prelude::{FheDecrypt as FheDecrypt08, FheEncrypt as FheEncrypt08};
use tfhe_08::safe_serialization::{
    DeserializationConfig as DeserializationConfig08, SerializationConfig as SerializationConfig08,
};
use tfhe_08::{
    set_server_key as set_server_key_08, CompressedServerKey as CompressedServerKey08,
    FheUint8 as FheUint8V08, ServerKey as ServerKey08,
};
#[allow(unused_imports)]
use tfhe_18::prelude::{FheDecrypt as FheDecrypt18, FheEncrypt as FheEncrypt18};
use tfhe_18::safe_serialization::{
    DeserializationConfig as DeserializationConfig18, SerializationConfig as SerializationConfig18,
};
use tfhe_18::{
    set_server_key as set_server_key_18, CompressedServerKey as CompressedServerKey18,
    FheUint8 as FheUint8V18, ServerKey as ServerKey18,
};

/// Cache entry: deserialized ServerKey + insertion time.
struct CachedKey {
    runtime: CachedRuntime,
    inserted_at: Instant,
}

/// The 0.8 runtime remains available while already-open browser tabs age out.
/// A 1.8 browser opts into the matching runtime with `tfheVersion: "1.8"`.
#[derive(Clone)]
enum CachedRuntime {
    V08 {
        key: Arc<ServerKey08>,
        wire_format: WireFormat08,
    },
    V18 {
        key: Arc<ServerKey18>,
    },
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum TfheVersion {
    V08,
    V18,
}

impl TfheVersion {
    fn from_request(value: Option<&str>) -> Result<Self, &'static str> {
        match value {
            None | Some("0.8") => Ok(Self::V08),
            Some("1.8") => Ok(Self::V18),
            Some(_) => Err("Unsupported tfheVersion; expected 0.8 or 1.8"),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::V08 => "0.8",
            Self::V18 => "1.8",
        }
    }
}

/// TFHE 0.8 exposed both raw bincode and safe serialization. Safe is preferred;
/// raw bincode remains readable solely for pre-bridge browser tabs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WireFormat08 {
    Safe,
    Legacy,
}

/// Shared application state with server key cache.
pub struct AppState {
    /// Cache keyed by a hash of the full base64 server key.
    /// Entries expire after [`CACHE_TTL_SECS`].
    cache: Mutex<HashMap<String, CachedKey>>,
}

const CACHE_TTL_SECS: u64 = 600; // 10 minutes
const SERVER_KEY_SIZE_LIMIT: u64 = 96 * 1024 * 1024;
const CIPHERTEXT_SIZE_LIMIT: u64 = 16 * 1024 * 1024;

fn deserialize_server_key_08(
    bytes: &[u8],
) -> Result<(CompressedServerKey08, WireFormat08), String> {
    match DeserializationConfig08::new(SERVER_KEY_SIZE_LIMIT)
        .disable_conformance()
        .deserialize_from(bytes)
    {
        Ok(key) => Ok((key, WireFormat08::Safe)),
        Err(safe_error) => {
            if bytes.len() as u64 > SERVER_KEY_SIZE_LIMIT {
                return Err(format!(
                    "safe serialization rejected input: {safe_error}; legacy input exceeds {SERVER_KEY_SIZE_LIMIT} bytes"
                ));
            }
            bincode::deserialize(bytes)
                .map(|key| (key, WireFormat08::Legacy))
                .map_err(|legacy_error| {
                    format!(
                        "safe serialization rejected input: {safe_error}; legacy bincode rejected input: {legacy_error}"
                    )
                })
        }
    }
}

fn deserialize_ciphertext_08(
    bytes: &[u8],
    wire_format: WireFormat08,
) -> Result<FheUint8V08, String> {
    match wire_format {
        WireFormat08::Safe => DeserializationConfig08::new(CIPHERTEXT_SIZE_LIMIT)
            .disable_conformance()
            .deserialize_from(bytes)
            .map_err(|error| format!("safe serialization rejected input: {error}")),
        WireFormat08::Legacy => {
            if bytes.len() as u64 > CIPHERTEXT_SIZE_LIMIT {
                return Err(format!(
                    "legacy ciphertext exceeds {CIPHERTEXT_SIZE_LIMIT} bytes"
                ));
            }
            bincode::deserialize(bytes)
                .map_err(|error| format!("legacy bincode rejected input: {error}"))
        }
    }
}

fn serialize_ciphertext_08(
    ciphertext: &FheUint8V08,
    wire_format: WireFormat08,
) -> Result<Vec<u8>, String> {
    match wire_format {
        WireFormat08::Safe => {
            let mut bytes = Vec::new();
            SerializationConfig08::new(CIPHERTEXT_SIZE_LIMIT)
                .serialize_into(ciphertext, &mut bytes)
                .map_err(|error| format!("safe serialization failed: {error}"))?;
            Ok(bytes)
        }
        WireFormat08::Legacy => bincode::serialize(ciphertext)
            .map_err(|error| format!("legacy bincode serialization failed: {error}")),
    }
}

fn deserialize_server_key_18(bytes: &[u8]) -> Result<CompressedServerKey18, String> {
    DeserializationConfig18::new(SERVER_KEY_SIZE_LIMIT)
        .disable_conformance()
        .deserialize_from(bytes)
        .map_err(|error| format!("safe serialization rejected input: {error}"))
}

fn deserialize_ciphertext_18(bytes: &[u8]) -> Result<FheUint8V18, String> {
    DeserializationConfig18::new(CIPHERTEXT_SIZE_LIMIT)
        .disable_conformance()
        .deserialize_from(bytes)
        .map_err(|error| format!("safe serialization rejected input: {error}"))
}

fn serialize_ciphertext_18(ciphertext: &FheUint8V18) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    SerializationConfig18::new(CIPHERTEXT_SIZE_LIMIT)
        .serialize_into(ciphertext, &mut bytes)
        .map_err(|error| format!("safe serialization failed: {error}"))?;
    Ok(bytes)
}

impl AppState {
    pub fn new() -> Self {
        Self {
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// Get or deserialize a ServerKey. Returns a cheap-clone runtime handle whose
    /// key is held behind an Arc (`set_server_key` takes an owned clone).
    ///
    /// Deserializing + decompressing a TFHE server key is expensive (1-5s), so
    /// results are cached per unique key for [`CACHE_TTL_SECS`]. The cache is
    /// keyed by a hash of the *full* base64 string (not a prefix) to avoid
    /// collisions between keys that share a common prefix.
    fn get_or_insert_key(
        &self,
        version: TfheVersion,
        key_b64: &str,
        key_bytes: &[u8],
    ) -> Result<CachedRuntime, String> {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        version.hash(&mut hasher);
        key_b64.hash(&mut hasher);
        let cache_key = hasher.finish().to_string();
        let mut cache = self.cache.lock().map_err(|_| "Cache lock poisoned")?;

        // Evict expired entries.
        cache.retain(|_, v| v.inserted_at.elapsed().as_secs() < CACHE_TTL_SECS);

        if let Some(entry) = cache.get(&cache_key) {
            if entry.inserted_at.elapsed().as_secs() < CACHE_TTL_SECS {
                return Ok(entry.runtime.clone());
            }
        }

        // Deserialize compressed key (expensive) and decompress.
        let runtime = match version {
            TfheVersion::V08 => {
                let (compressed_key, wire_format) = deserialize_server_key_08(key_bytes)
                    .map_err(|error| format!("TFHE 0.8 ServerKey deserialize: {error}"))?;
                CachedRuntime::V08 {
                    key: Arc::new(compressed_key.decompress()),
                    wire_format,
                }
            }
            TfheVersion::V18 => {
                let compressed_key = deserialize_server_key_18(key_bytes)
                    .map_err(|error| format!("TFHE 1.8 ServerKey deserialize: {error}"))?;
                CachedRuntime::V18 {
                    key: Arc::new(compressed_key.decompress()),
                }
            }
        };
        cache.insert(
            cache_key,
            CachedKey {
                runtime: runtime.clone(),
                inserted_at: Instant::now(),
            },
        );
        Ok(runtime)
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ComputeRequest {
    server_key: String,
    ct_a: String,
    ct_b: String,
    tfhe_version: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ComputeResponse {
    ct_result: String,
    operation: String,
    plaintext_accessed: bool,
    scheme: String,
    bootstrapping: String,
    tfhe_version: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ErrorResponse {
    error: String,
    plaintext_accessed: bool,
}

fn error_response(status: StatusCode, msg: &str) -> (StatusCode, Json<ErrorResponse>) {
    (
        status,
        Json(ErrorResponse {
            error: msg.to_string(),
            plaintext_accessed: false,
        }),
    )
}

/// Return only the first 12 characters of a base64 payload for logging —
/// never log full ciphertexts or keys.
fn preview(b64: &str) -> &str {
    &b64[..std::cmp::min(12, b64.len())]
}

/// Core FHE computation: deserialize two `FheUint8` ciphertexts, add them with
/// gate bootstrapping, and serialize the encrypted result.
///
/// This function is intentionally free of HTTP/async concerns so it can be unit
/// tested directly against real TFHE keys.
fn fhe_add(
    ct_a_bytes: &[u8],
    ct_b_bytes: &[u8],
    runtime: CachedRuntime,
) -> Result<Vec<u8>, String> {
    match runtime {
        CachedRuntime::V08 { key, wire_format } => {
            // Server keys are thread-local in both TFHE runtimes, so register
            // the matching key inside the same blocking task that computes.
            set_server_key_08((*key).clone());
            let ct_a = deserialize_ciphertext_08(ct_a_bytes, wire_format)
                .map_err(|error| format!("ctA deserialize: {error}"))?;
            let ct_b = deserialize_ciphertext_08(ct_b_bytes, wire_format)
                .map_err(|error| format!("ctB deserialize: {error}"))?;
            let ct_result = &ct_a + &ct_b;
            serialize_ciphertext_08(&ct_result, wire_format)
                .map_err(|error| format!("Result serialize: {error}"))
        }
        CachedRuntime::V18 { key } => {
            set_server_key_18((*key).clone());
            let ct_a = deserialize_ciphertext_18(ct_a_bytes)
                .map_err(|error| format!("ctA deserialize: {error}"))?;
            let ct_b = deserialize_ciphertext_18(ct_b_bytes)
                .map_err(|error| format!("ctB deserialize: {error}"))?;
            let ct_result = &ct_a + &ct_b;
            serialize_ciphertext_18(&ct_result)
                .map_err(|error| format!("Result serialize: {error}"))
        }
    }
}

/// POST /compute/add
///
/// Receives two base64-encoded `FheUint8` ciphertexts and a base64-encoded
/// compressed `ServerKey`. Performs gate-bootstrapped homomorphic addition and
/// returns the encrypted result.
///
/// The server never holds a `ClientKey` and cannot decrypt any ciphertext.
///
/// Performance notes:
/// - ServerKey deserialization: 1-5 seconds (cached after first use per key).
/// - FheUint8 addition with gate bootstrapping: 100ms-2s depending on hardware.
/// - FheUint8 range: 0-255; addition wraps modulo 256 on overflow.
#[tracing::instrument(skip_all)]
pub async fn compute_add(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<ComputeRequest>,
) -> Result<Json<ComputeResponse>, (StatusCode, Json<ErrorResponse>)> {
    let version = TfheVersion::from_request(payload.tfhe_version.as_deref())
        .map_err(|message| error_response(StatusCode::BAD_REQUEST, message))?;
    tracing::info!(
        ct_a = %preview(&payload.ct_a),
        ct_b = %preview(&payload.ct_b),
        tfhe_version = version.as_str(),
        "received add request"
    );

    let sk_bytes = BASE64
        .decode(&payload.server_key)
        .map_err(|_| error_response(StatusCode::BAD_REQUEST, "Invalid base64 in serverKey"))?;
    let ct_a_bytes = BASE64
        .decode(&payload.ct_a)
        .map_err(|_| error_response(StatusCode::BAD_REQUEST, "Invalid base64 in ctA"))?;
    let ct_b_bytes = BASE64
        .decode(&payload.ct_b)
        .map_err(|_| error_response(StatusCode::BAD_REQUEST, "Invalid base64 in ctB"))?;

    // Get or cache the (expensive to deserialize) server key.
    let runtime = state
        .get_or_insert_key(version, &payload.server_key, &sk_bytes)
        .map_err(|e| {
            tracing::warn!(error = %e, "server key rejected");
            error_response(StatusCode::BAD_REQUEST, "Invalid server key")
        })?;

    // FHE operations are CPU-bound. Key registration and computation both run
    // inside this blocking task because each TFHE runtime stores its key in
    // thread-local state.
    let result = tokio::task::spawn_blocking(move || fhe_add(&ct_a_bytes, &ct_b_bytes, runtime))
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "compute task panicked or was cancelled");
            error_response(StatusCode::INTERNAL_SERVER_ERROR, "Computation failed")
        })?
        .map_err(|e| {
            tracing::warn!(error = %e, "ciphertext rejected");
            error_response(StatusCode::BAD_REQUEST, "Invalid ciphertext")
        })?;

    let ct_result_b64 = BASE64.encode(&result);
    tracing::info!(
        result = %preview(&ct_result_b64),
        plaintext_accessed = false,
        "add complete"
    );

    Ok(Json(ComputeResponse {
        ct_result: ct_result_b64,
        operation: "tfhe_fhe_add".to_string(),
        plaintext_accessed: false,
        scheme: "TFHE-rs".to_string(),
        bootstrapping: "gate_bootstrapping_per_operation".to_string(),
        tfhe_version: version.as_str().to_string(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tfhe_08::{
        generate_keys as generate_keys_08, ClientKey as ClientKey08,
        ConfigBuilder as ConfigBuilder08,
    };
    use tfhe_18::{
        generate_keys as generate_keys_18, ClientKey as ClientKey18,
        ConfigBuilder as ConfigBuilder18,
    };

    fn test_keys_08() -> (ClientKey08, ServerKey08) {
        generate_keys_08(ConfigBuilder08::default().build())
    }

    fn test_keys_18() -> (ClientKey18, ServerKey18) {
        generate_keys_18(ConfigBuilder18::default().build())
    }

    fn encrypt_bytes_08(value: u8, key: &ClientKey08, wire_format: WireFormat08) -> Vec<u8> {
        let ciphertext = FheUint8V08::encrypt(value, key);
        serialize_ciphertext_08(&ciphertext, wire_format).unwrap()
    }

    fn decrypt_result_08(bytes: &[u8], key: &ClientKey08, wire_format: WireFormat08) -> u8 {
        deserialize_ciphertext_08(bytes, wire_format)
            .unwrap()
            .decrypt(key)
    }

    fn serialize_server_key_08(key: &CompressedServerKey08, wire_format: WireFormat08) -> Vec<u8> {
        match wire_format {
            WireFormat08::Safe => {
                let mut bytes = Vec::new();
                SerializationConfig08::new(SERVER_KEY_SIZE_LIMIT)
                    .serialize_into(key, &mut bytes)
                    .unwrap();
                bytes
            }
            WireFormat08::Legacy => bincode::serialize(key).unwrap(),
        }
    }

    fn encrypt_bytes_18(value: u8, key: &ClientKey18) -> Vec<u8> {
        let ciphertext = FheUint8V18::encrypt(value, key);
        serialize_ciphertext_18(&ciphertext).unwrap()
    }

    fn decrypt_result_18(bytes: &[u8], key: &ClientKey18) -> u8 {
        deserialize_ciphertext_18(bytes).unwrap().decrypt(key)
    }

    fn serialize_server_key_18(key: &CompressedServerKey18) -> Vec<u8> {
        let mut bytes = Vec::new();
        SerializationConfig18::new(SERVER_KEY_SIZE_LIMIT)
            .serialize_into(key, &mut bytes)
            .unwrap();
        bytes
    }

    #[test]
    fn preview_truncates_and_is_safe_on_short_input() {
        assert_eq!(preview("abcdefghijklmnop"), "abcdefghijkl");
        assert_eq!(preview("short"), "short");
        assert_eq!(preview(""), "");
    }

    #[test]
    fn version_selection_is_explicit_and_backwards_compatible() {
        assert_eq!(TfheVersion::from_request(None), Ok(TfheVersion::V08));
        assert_eq!(TfheVersion::from_request(Some("0.8")), Ok(TfheVersion::V08));
        assert_eq!(TfheVersion::from_request(Some("1.8")), Ok(TfheVersion::V18));
        assert!(TfheVersion::from_request(Some("future")).is_err());
    }

    #[test]
    fn tfhe_18_add_matches_plaintext_addition() {
        let (client_key, server_key) = test_keys_18();

        let (a, b) = (7u8, 200u8);
        let result = fhe_add(
            &encrypt_bytes_18(a, &client_key),
            &encrypt_bytes_18(b, &client_key),
            CachedRuntime::V18 {
                key: Arc::new(server_key),
            },
        )
        .unwrap();

        let got = decrypt_result_18(&result, &client_key);
        assert_eq!(got, a.wrapping_add(b)); // 207
    }

    #[test]
    fn tfhe_08_safe_add_remains_available_for_open_tabs() {
        let (client_key, server_key) = test_keys_08();

        let (a, b) = (11u8, 31u8);
        let result = fhe_add(
            &encrypt_bytes_08(a, &client_key, WireFormat08::Safe),
            &encrypt_bytes_08(b, &client_key, WireFormat08::Safe),
            CachedRuntime::V08 {
                key: Arc::new(server_key),
                wire_format: WireFormat08::Safe,
            },
        )
        .unwrap();

        let got = decrypt_result_08(&result, &client_key, WireFormat08::Safe);
        assert_eq!(got, 42);
    }

    #[test]
    fn tfhe_08_legacy_add_wraps_modulo_256_on_overflow() {
        let (client_key, server_key) = test_keys_08();

        let (a, b) = (200u8, 100u8);
        let result = fhe_add(
            &encrypt_bytes_08(a, &client_key, WireFormat08::Legacy),
            &encrypt_bytes_08(b, &client_key, WireFormat08::Legacy),
            CachedRuntime::V08 {
                key: Arc::new(server_key),
                wire_format: WireFormat08::Legacy,
            },
        )
        .unwrap();

        let got = decrypt_result_08(&result, &client_key, WireFormat08::Legacy);
        assert_eq!(got, a.wrapping_add(b)); // 44
    }

    #[test]
    fn tfhe_18_add_rejects_garbage_ciphertext() {
        let (client_key, server_key) = test_keys_18();
        let valid = encrypt_bytes_18(1, &client_key);
        assert!(fhe_add(
            &valid,
            b"not a ciphertext",
            CachedRuntime::V18 {
                key: Arc::new(server_key),
            },
        )
        .is_err());
    }

    #[test]
    fn tfhe_18_cache_returns_same_arc_on_hit() {
        let (client_key, _) = test_keys_18();
        let bytes = serialize_server_key_18(&CompressedServerKey18::new(&client_key));

        let state = AppState::new();
        let first = state
            .get_or_insert_key(TfheVersion::V18, "client-18", &bytes)
            .unwrap();
        let second = state
            .get_or_insert_key(TfheVersion::V18, "client-18", &bytes)
            .unwrap();
        match (first, second) {
            (CachedRuntime::V18 { key: first }, CachedRuntime::V18 { key: second }) => {
                assert!(Arc::ptr_eq(&first, &second), "second call should hit cache");
            }
            _ => panic!("TFHE 1.8 cache returned the wrong runtime"),
        }
    }

    #[test]
    fn tfhe_08_cache_accepts_safe_server_key_during_transition() {
        let (client_key, _) = test_keys_08();
        let bytes =
            serialize_server_key_08(&CompressedServerKey08::new(&client_key), WireFormat08::Safe);

        let state = AppState::new();
        let runtime = state
            .get_or_insert_key(TfheVersion::V08, "safe-08-client", &bytes)
            .unwrap();
        assert!(matches!(
            runtime,
            CachedRuntime::V08 {
                wire_format: WireFormat08::Safe,
                ..
            }
        ));
    }

    #[test]
    fn tfhe_08_cache_accepts_legacy_server_key_during_transition() {
        let (client_key, _) = test_keys_08();
        let bytes = serialize_server_key_08(
            &CompressedServerKey08::new(&client_key),
            WireFormat08::Legacy,
        );

        let state = AppState::new();
        let runtime = state
            .get_or_insert_key(TfheVersion::V08, "legacy-client", &bytes)
            .unwrap();
        assert!(matches!(
            runtime,
            CachedRuntime::V08 {
                wire_format: WireFormat08::Legacy,
                ..
            }
        ));
    }

    #[test]
    fn cache_rejects_invalid_server_key() {
        let state = AppState::new();
        assert!(state
            .get_or_insert_key(TfheVersion::V08, "bad-08", b"not a server key")
            .is_err());
        assert!(state
            .get_or_insert_key(TfheVersion::V18, "bad-18", b"not a server key")
            .is_err());
    }
}
