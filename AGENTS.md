# AGENTS.md — liskov-runtime-cargo

This repository owns native first contact for Liskov-managed Acurast
Cargo/PRoot workloads. It produces the static AArch64
`liskov-runtime-contact` helper and its pinned static Dropbear companions.

## Scope

- Keep the helper independent of the `liskov-rs` checkout. It consumes the
  published signed runtime-bootstrap v2 contract.
- The supervisor owns authenticated first contact, required runtime-environment
  retrieval, exact customer-process handoff, provider adapters, and the narrow
  job-bound Lockbox lookup for its server-owned Blackbox config. General
  customer Lockbox installation and bootstrap ZIP integration remain separate
  work.
- Distribution is through GitHub Releases, not crates.io and not a runtime
  download. Release-manifest v2 separately identifies and attests the helper,
  Dropbear server, and Dropbear key generator.

## Security invariants

- Fail closed: never execute the customer command unless signed bootstrap
  contact succeeds and every response binding is valid.
- Discover identity and sign only through the abstract Unix bridge named by
  `BRIDGE_SOCKET`.
- Build and sign one request per process. HTTP retries must reuse the identical
  nonce, timestamp, signature, and serialized request body.
- Accept HTTPS endpoints only. Do not follow redirects.
- Never log request or response bodies, signatures, bridge responses, nonces,
  processor identity, or customer arguments.
- Keep bridge and HTTP reads bounded.
- Do not invoke a shell for customer command handoff.

## Contract changes

The runtime-bootstrap domain, canonical signed bytes, retry classification,
identity binding, and stable exit codes are public contracts. Update their
golden tests and the orchestrator decision record in the same logical change.

Tests must remain offline. Put bridge, clock, randomness, HTTP, sleep, and
command execution behind the existing seams rather than calling live services.

## Validation

Before every commit, run:

```sh
cargo fmt --all --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo build --workspace --all-targets --locked
cargo test --workspace --all-features --locked
```

The GitHub ARM64 job additionally builds
`aarch64-unknown-linux-musl`, runs `--version`, and checks the ELF machine and
absence of a dynamic interpreter.
