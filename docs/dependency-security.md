# Dependency Security

CI runs RustSec's `cargo audit` against every change. Compatible vulnerable dependencies are updated in `Cargo.lock`; the project's direct HTTPS client uses `reqwest` 0.12 with the current Rustls stack.

## Scoped SSI 0.6 Advisories

The project currently uses SSI 0.6 for VC 1.x `JsonWebSignature2020` interoperability. That release unconditionally includes older crypto algorithms and an older `reqwest` client, even when an application does not call those paths. The audit exceptions in `.cargo/audit.toml` are limited to those unreachable paths:

- `RUSTSEC-2022-0093`, `RUSTSEC-2023-0071`, and `RUSTSEC-2024-0344` affect private-key operations in the legacy Ed25519, RSA, and Curve25519 implementations. Production signing happens on the OpenPGP card, the CLI does not accept software private keys, and RSA credentials are outside the supported Ed25519 profile. Public Ed25519 proof verification does not exercise the affected private-key operations.
- `RUSTSEC-2025-0009`, `RUSTSEC-2026-0098`, `RUSTSEC-2026-0099`, and `RUSTSEC-2026-0104` are present only through SSI VC's built-in HTTP status client. The CLI never calls that client. DID documents and status lists are fetched exclusively by `SafeDidWebResolver` and `fetch_public_https`, using the direct `reqwest` 0.12 dependency with public-address validation, DNS pinning, no proxy, no redirects, timeouts, and body-size limits.

These are not blanket exceptions: the exact advisory IDs are pinned so any new RustSec finding still fails CI. Remove the exceptions when SSI is upgraded to a release that no longer brings these legacy paths into the dependency graph.
