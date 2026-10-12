# blind-oracle-api

[![CI](https://github.com/systemslibrarian/crypto-lab-blind-oracle-api/actions/workflows/ci.yml/badge.svg)](https://github.com/systemslibrarian/crypto-lab-blind-oracle-api/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.82%2B-orange.svg)](https://www.rust-lang.org)

A Rust back-end that performs **fully homomorphic encrypted addition** on
`FheUint8` ciphertexts using [TFHE-rs](https://github.com/zama-ai/tfhe-rs).
The server is a **blind oracle**: it computes on ciphertexts it can never
decrypt, because the decryption key never leaves the browser.

## What It Is

The browser client generates a TFHE key pair, encrypts two 8-bit integers, and
sends the two ciphertexts plus an *evaluation key* (`ServerKey`) to this API.
The server computes the homomorphic sum via gate bootstrapping and returns the
encrypted result — without ever accessing plaintext. The `ClientKey` (the only
key that can decrypt) never leaves the browser, so the server holds only the
ability to *compute*, never to *read*.

TFHE is a lattice-based FHE scheme with post-quantum security assumptions.

## When to Use This Pattern

- **Privacy-preserving server-side computation** — a client needs a server to
  compute on its data without revealing the inputs or outputs.
- **Demonstrating FHE gate bootstrapping** — every `FheUint8` operation resets
  the noise budget automatically, enabling unlimited computation depth with no
  manual noise management.
- **Blind oracle trust model** — the server holds only an evaluation key and
  never possesses decryption capability.
- **Post-quantum-secure computation** — TFHE's lattice hardness assumption is
  believed to resist quantum attacks, unlike RSA or ECC.

> **Not** for high-throughput or low-latency workloads: a single `FheUint8`
> addition takes 100 ms–2 s. Use conventional encryption or MPC when
> sub-millisecond latency is required.

## Architecture

```
  Browser (holds ClientKey)                    blind-oracle-api (this server)
  ─────────────────────────                    ──────────────────────────────
  1. generate_keys()                            never sees ClientKey
  2. encrypt(a), encrypt(b)  ──ciphertexts──▶
  3. send ServerKey          ──eval key─────▶   set_server_key(server_key)
                                                deserialize ct_a, ct_b
                                                ct_result = ct_a + ct_b   ◀── bootstrapped
  4. decrypt(ct_result)      ◀──ciphertext───   (plaintext never accessed)
```

The server-side flow lives in three small modules:

| File                   | Responsibility                                              |
| ---------------------- | ----------------------------------------------------------- |
| `src/main.rs`          | Router, middleware (CORS, body limit, timeout, concurrency limit, tracing), graceful shutdown. |
| `src/routes/compute.rs`| `POST /compute/add` handler, server-key cache, and the testable `fhe_add` core. |
| `src/fhe.rs`           | TFHE-rs context confirmation at startup.                    |

## API

### `GET /`
Service discovery. Returns the service name and available routes.

### `GET /health`
Liveness/readiness probe. Cheap and side-effect free.

```json
{ "status": "ok", "scheme": "TFHE-rs", "fhe": true, "tfheVersions": ["0.8", "1.8"] }
```

### `POST /compute/add`
Homomorphic addition of two encrypted 8-bit integers.

**Request body** (`serverKey`, `ctA`, and `ctB` are base64-encoded):

| Field         | Type   | Description                                                            |
| ------------- | ------ | ---------------------------------------------------------------------- |
| `serverKey`   | string | TFHE safe-serialized **compressed** `ServerKey`.                        |
| `ctA`         | string | TFHE safe-serialized `FheUint8` ciphertext (operand A).                 |
| `ctB`         | string | TFHE safe-serialized `FheUint8` ciphertext (operand B).                 |
| `tfheVersion` | string | Runtime/wire version: `"1.8"`; omitted requests use the 0.8 bridge.    |

TFHE safe serialization adds type and version checks plus explicit size limits.
TFHE 1.8 cannot deserialize 0.8 server keys, so requests explicitly select their
matching runtime. The API temporarily retains its 0.8 safe and raw-bincode paths
for already-open browser tabs; a response always uses the same TFHE and wire
version as its request.

```jsonc
// POST /compute/add
{ "serverKey": "<base64>", "ctA": "<base64>", "ctB": "<base64>", "tfheVersion": "1.8" }
```

**Success — `200 OK`:**

```jsonc
{
  "ctResult": "<base64 FheUint8>",   // encrypted sum, wraps mod 256 on overflow
  "operation": "tfhe_fhe_add",
  "plaintextAccessed": false,        // always false — the server cannot decrypt
  "scheme": "TFHE-rs",
  "bootstrapping": "gate_bootstrapping_per_operation",
  "tfheVersion": "1.8"
}
```

**Errors — `400 Bad Request`:** `{ "error": "...", "plaintextAccessed": false }`
with a specific message: `Invalid base64 in serverKey` / `... in ctA` / `... in ctB`,
`Invalid server key`, or `Invalid ciphertext`.

## Running Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-blind-oracle-api.git
cd crypto-lab-blind-oracle-api
cargo run --release
```

The server listens on port `3001` by default; override with `PORT`:

```bash
PORT=8080 cargo run --release
```

> The primary TFHE-rs 1.8 runtime selects its platform backend at compile time.
> This service disables its optional AVX-512 default so the binary remains
> portable across Render's x86-64 hosts and local Arm64 development machines.
> A target-specific TFHE-rs 0.8 compatibility runtime supports rolling upgrades.
> Rust 1.91.1 or newer is required. The first build takes 5–10 minutes;
> subsequent builds are incremental.

### With Docker

```bash
docker build -t blind-oracle-api .
docker run -p 3001:3001 blind-oracle-api
```

The image runs as a non-root user and ships a `HEALTHCHECK` against `/health`.

## Configuration

| Variable   | Default | Description                                          |
| ---------- | ------- | ---------------------------------------------------- |
| `PORT`     | `3001`  | TCP port to listen on.                               |
| `RUST_LOG` | `info`  | Log filter, e.g. `RUST_LOG=blind_oracle_api=debug`.  |

Additional safety limits (compile-time constants in `src/main.rs`): a 100 MB
request-body cap, a 60 s per-request timeout, and a concurrency limit equal to
available CPU parallelism.

## Testing

```bash
cargo test --release
```

The suite generates **real** TFHE keys and performs genuine homomorphic
operations — it verifies that the encrypted sum decrypts to the correct
plaintext, that addition wraps modulo 256, that the server-key cache returns a
shared handle on a hit, and that malformed keys/ciphertexts are rejected. Because
it runs real FHE, it is slower than a typical Rust test suite.

## Security Model

- The server **never** holds or derives a `ClientKey` and cannot decrypt any
  ciphertext. `plaintextAccessed` is always `false`.
- Full ciphertexts and keys are **never** logged — only short, non-sensitive
  previews (first 12 base64 characters).
- CORS is restricted to the demo origins (`systemslibrarian.github.io` and
  `localhost:5173`).
- This is a demonstration of the blind-oracle pattern, not a hardened
  multi-tenant service; there is no authentication or rate limiting beyond the
  concurrency cap.

## Live Demo

Back-end for the Blind Oracle experiment at
[systemslibrarian.github.io/crypto-lab/](https://systemslibrarian.github.io/crypto-lab/).
Enter any two numbers (0–255) and verify the server returns the correct
encrypted result without ever seeing plaintext.

## Part of the Crypto-Lab Suite

One component of the [Crypto-Lab](https://systemslibrarian.github.io/crypto-lab/)
suite of cryptographic demonstrations.

## License

[MIT](LICENSE) © 2026 Paul Clark

---

> *Whether you eat or drink or whatever you do, do it all for the glory of God.* — 1 Corinthians 10:31
