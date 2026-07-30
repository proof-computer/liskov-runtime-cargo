# liskov-runtime-cargo

`liskov-runtime-contact` is the native first-contact helper for
Liskov-managed workloads running in Acurast Cargo/PRoot images.

It discovers the active Acurast deployment and processor through the Cargo
bridge, signs one Liskov runtime-bootstrap v2 request with the deployment's
Ed25519 key, waits for bounded authenticated contact, and then replaces itself
with the customer command. If identity, signing, transport, or bootstrap
validation fails, the customer command does not start.

When `PROOF_SLIPWAY_BOOTSTRAP` contains the Liskov-owned `x.pc` extension, the
helper also emits bounded pre-contact evidence before bridge discovery and once
more on terminal contact failure. This bearer-authenticated evidence is
diagnostic only: it never authorizes command execution or replaces the signed
runtime-bootstrap gate.

## Supported runtime

- 64-bit AArch64 Cargo/PRoot workloads
- Acurast Android processor runtime 1.25.0 or newer
- an HTTPS Liskov core endpoint

The release binary is statically linked with Rustls and bundled Web PKI roots.
It does not depend on OpenSSL or the image's CA store.

## Usage

```text
liskov-runtime-contact [--core-url URL] -- <command> [args...]
```

For example:

```sh
./liskov-runtime-contact -- /opt/my-app/bin/server --listen 0.0.0.0:8080
```

The core URL is selected in this order:

1. `--core-url URL`
2. `LISKOV_CORE_URL`
3. `https://liskov.proof.computer`

Only HTTPS URLs without user information, a query, or a fragment are accepted.
`BRIDGE_SOCKET` is required and is supplied by the Acurast Cargo runtime.

The helper writes concise, non-secret diagnostics to stderr. It never logs
bridge replies, signed request or response bodies, signatures, processor
identity, pre-contact tokens, or the customer command.

## Exit status

| Status | Meaning |
| --- | --- |
| `2` | CLI or configuration error |
| `70` | Bridge, identity, signature, protocol, or permanent server rejection |
| `75` | Transport failure or retry exhaustion |
| `126` | The customer command could not be executed |

After a successful `exec`, the customer process has normal process and exit
behavior.

For bounded release canaries whose Shell host does not retain stderr,
`--diagnostic-exit-codes` replaces status `70`/`75` with a non-secret stage
code. This flag is an internal canary interface, not a customer compatibility
surface:

| Status | Stage |
| --- | --- |
| `80`–`82` | Bridge setup or deployment identity |
| `83`–`84` | Deployment public key |
| `85`–`86` | Assigned-processor binding |
| `87`–`88` | Deployment signing |
| `89` | Request construction |
| `90` | Permanent server rejection |
| `91`–`92` | Response validation or binding |
| `93`–`94` | Runtime randomness or clock |
| `95` | Retry exhaustion |

The flag changes only failure reporting: contact remains fail closed and the
customer command is never started after an error.

Liskov-controlled canaries may also use the hidden `--bridge-probe` flag. It
checks unique decimal `UInt` request IDs and the helper's incompatible long
request ID across the bounded Cargo bridge surface, including a
domain-separated harmless Ed25519 signing call. Bounded read-only calls run in
dependency order before signing; the probe stops at the first decisive failure
and gives signing the remainder of the shared 15-second budget. If the first
`processor_version` call times out, the probe records that attempt as
non-terminal warm-up evidence and retries it once with a fresh decimal `UInt`
ID; a second timeout is terminal. The long-ID comparison runs last and is
evidence only. The probe emits only method, ID-style, closed outcome, and
optional numeric JSON-RPC code fields.

## Retry boundary

Retryable bridge failures and incomplete identity replies use a 250 ms first
delay and then 2-second intervals before the helper generates its nonce and
timestamp. The helper signs once per process and reuses the exact serialized
request for all HTTP attempts. Identity discovery and HTTP contact each allow
at most 30 attempts, share one 60-second elapsed-time ceiling, and each HTTP
attempt has a 10-second timeout.

Pre-contact reporting is independent of this retry loop. The started and
terminal reports each receive one HTTP attempt, a two-second timeout, an 8-KiB
response limit, and strict response binding.

## Release

Each release publishes:

```text
liskov-runtime-contact-v<VERSION>-aarch64-unknown-linux-musl.tar.gz
SHA256SUMS
```

The archive contains the helper binary, this README, and the Apache-2.0
license. Verify it before extraction:

```sh
sha256sum --check SHA256SUMS
```

## Development

The repository uses Rust 2024 with MSRV 1.85. Validation is offline:

```sh
cargo fmt --all --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo build --workspace --all-targets --locked
cargo test --workspace --all-features --locked
```

Bootstrap ZIP integration is intentionally not part of this first slice.
