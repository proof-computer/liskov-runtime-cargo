# liskov-runtime-cargo

`liskov-runtime-contact` is the native bootstrap and process supervisor for
Liskov-managed workloads running in Acurast Cargo/PRoot images.

It discovers the active Acurast deployment and processor through the Cargo
bridge, signs one Liskov runtime-bootstrap v2 request with the deployment's
Ed25519 key and waits for bounded authenticated contact. When that bound
response enables runtime environment retrieval, the helper signs a separate
UID-bound v2 request, rejects endpoint or response substitution, validates
every environment name, and captures those values before customer startup. It
then becomes a child subreaper, starts the customer command in a dedicated
process group, forwards supported signals, reaps descendants, and returns the
customer's exact exit status or terminating signal after cleanup. If identity,
signing, transport, or bootstrap validation fails, the customer command does
not start.

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

The supervisor writes concise, non-secret diagnostics to stderr. It never logs
bridge replies, signed request or response bodies, signatures, processor
identity, pre-contact tokens, or the customer command.

After successful contact it also emits best-effort, deployment-signed Cargo
diagnostic-v4 observations. These observations use one monotonic sequence for
the runtime instance and include nested process-attempt counters. Delivery is
bounded to five seconds per request with a bounded response and never changes
workload execution.

## Optional stdout/stderr forwarding

Output forwarding starts only when the signed bootstrap response contains the
exact policy decision `{"logging":{"enabled":true}}` and
`BLACKBOX_LOG_CONFIG` validates against the same application, deployment, and
job. The supervisor tees stdout and stderr to their normal local destinations,
then forwards separately encrypted records through Liskov's canonical
Blackbox sink protocol. UTF-8 chunks are labeled as text; binary chunks use
base64url framing. Every encrypted record binds the stream, process attempt,
monotonic output sequence, runtime instance, timestamp, byte length, and
truncation state.

Capture uses 3-KiB chunks, a 256-KiB-per-second admission limit, a 128-item
in-memory queue, at most 32 records and 256 KiB per request, five-second
requests, 16-KiB responses, and at most ten network requests per second. It
does not create a local durable spool. Queue or rate overflow produces only
bounded encrypted dropped-byte and dropped-chunk evidence. Network failure,
sink backpressure, invalid logging configuration, and the bounded 250-ms
terminal flush never block, restart, terminate, or change the customer result.
Customer output, the Blackbox DEK, factory token, request signatures, and
environment values never enter Cargo diagnostics.

The server-owned `loggingOutageCanary` bootstrap flag is accepted only when
logging is already explicitly enabled and the bound Blackbox configuration is
valid. For an exact release canary it makes every log request fail locally,
without changing capture limits, local stdout/stderr, supervision, diagnostics,
or the customer result. It is not a customer-authored policy field and never
enables logging by itself.

## Exit status

| Status | Meaning |
| --- | --- |
| `2` | CLI or configuration error |
| `70` | Bridge, identity, signature, protocol, or permanent server rejection |
| `75` | Transport failure or retry exhaustion |
| `126` | The customer command could not be started |

On Unix, normal exits and terminating signals are propagated exactly after the
customer process group and adopted descendants have been cleaned up.

## Supervision policy

The compatibility default is `never`: one customer attempt is run. A strict,
server-owned optional bootstrap block can select `on_failure` with either an
attempt limit from 0 through 10 restarts or the schedule end. Unknown or
malformed values fail closed to `never`. Restart delays use deterministic
equal jitter, a one-minute cap, a five-minute stability reset, and a five-second
schedule runway.

Non-default restart policy is currently limited to exact applications selected
by the Liskov control plane through `LISKOV_CARGO_SUPERVISION_CANARY_JSON`. The
variable is an internal fail-closed canary control, is removed before customer
startup, and is not a customer-authored policy surface. The bootstrap secret,
supervision canary control, and reserved Runtime SSH credential are removed
from the captured customer environment. Runtime values cannot reintroduce
those protected names.

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
first reproduces Acurast's Cargo-native example call:
`signer_publicKey` with `curve: "p256"`. That first connection receives the
remainder of the shared 15-second budget and is followed by the example's
`deployment_assignedProcessors` call. The probe then checks unique decimal
`UInt` request IDs and the helper's incompatible long request ID across
Liskov's stricter Cargo bridge surface, including a domain-separated harmless
Ed25519 signing call. It stops at the first decisive failure. The long-ID
comparison runs last and is evidence only. The probe emits only method,
ID-style, closed outcome, and optional numeric JSON-RPC code fields.

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
liskov-runtime-contact-v<VERSION>-aarch64-unknown-linux-musl
liskov-runtime-contact-v<VERSION>-aarch64-unknown-linux-musl.tar.gz
runtime-contact-release.json
SHA256SUMS
```

The raw binary, archive, and release manifest are attested. The manifest binds
the immutable tag and source commit to their exact digests and byte sizes. The
archive contains the helper binary, this README, and the Apache-2.0 license.
Verify the checksums before use:

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

Stable publication requires the repository's native AArch64 and emulated
Cargo/PRoot release gates in addition to these host checks.
