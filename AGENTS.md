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

Validation evidence is valid only for the exact tree that produced it. Re-run
the selected commands after the final merge, rebase, conflict resolution,
generated artifact update, or version change and before push.

Before every commit, run:

```sh
cargo fmt --all --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo build --workspace --all-targets --locked
cargo test --workspace --all-features --locked
scripts/test-package-release.sh
```

The GitHub ARM64 job is not merely a release backstop. A change to filesystem
operations, libc/syscalls, target-specific code, static dependencies, the
release binary, or packaging must also build the exact target before push:

```sh
rustup target add aarch64-unknown-linux-musl
cargo build --release --locked --target aarch64-unknown-linux-musl --bin liskov-runtime-contact
```

Run the maintained QEMU/PRoot smoke for changes to filesystem/syscall behavior,
first contact, process handoff, tunnel/fact probes, Dropbear, or the emulator
scripts. Match the exact commands in `.github/workflows/ci.yml`; do not
substitute a host-only test.
Files created through root or PRoot must be removed through the same privilege
boundary. A workload that passes and then fails unprivileged cleanup is a test
failure, not harmless teardown noise.

The ARM64 proof runs `--version`, checks the ELF machine, and refuses a dynamic
interpreter. A release tag is allowed only after the same commit's ordinary CI,
static-target build, QEMU/PRoot smoke and `scripts/test-package-release.sh` are
green. After tagging, inspect both release publication and registry
notification; a transport/DNS failure may be retried, but it is not evidence of
an invalid binary.
