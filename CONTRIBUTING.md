# Contributing

Thanks for your interest in the Blind Oracle API. This is a focused
demonstration project, so contributions that improve correctness, clarity,
security, or documentation are especially welcome.

## Development setup

```bash
git clone https://github.com/systemslibrarian/crypto-lab-blind-oracle-api.git
cd crypto-lab-blind-oracle-api
cargo build
```

> **Note:** TFHE-rs 1.8 requires Rust 1.91.1 or newer. Its optional AVX-512
> default is disabled so the service builds on both x86-64 Unix and Arm64
> development hosts; a target-specific 0.8 dependency provides rolling-client
> compatibility. The production Docker image remains Debian x86-64 on Render.
> The first build compiles both runtimes and takes 5–10 minutes.

## Before opening a pull request

Run the same checks CI runs:

```bash
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --release
```

The test suite generates real TFHE keys and performs genuine homomorphic
operations, so `cargo test` is slower than a typical Rust project — this is
expected.

## Design constraints

This server is a **blind oracle**. Any change must preserve these invariants:

1. The server never holds or derives a `ClientKey`.
2. The server never accesses plaintext (`plaintextAccessed` is always `false`).
3. Full ciphertexts and keys are never logged — only short, non-sensitive previews.

## Commit style

Use clear, conventional-style messages (`fix:`, `feat:`, `docs:`, `chore:`).
Keep changes small and reviewable.
