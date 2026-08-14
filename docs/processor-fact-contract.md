# Dormant processor-fact contract

Release `0.10.20` includes the `cargo-baseline-v1` collector, but does not
activate it. Existing runtime-bootstrap V2 producers omit `processorFacts`, so
the helper performs no processor-fact file reads, bridge signatures, DNS, or
HTTP requests.

## Authorization

`processorFacts` is raw optional data in the authenticated bootstrap response.
The helper removes it immediately, before runtime environment, diagnostics,
logging, access setup, or customer environment construction. It is then parsed
independently as this closed object:

```json
{
  "domain": "proof.liskov.processor-fact-authorization.v1",
  "authorizationId": "bounded-server-id",
  "challenge": "64-lowercase-hex-characters",
  "issuedAtMs": 0,
  "expiresAtMs": 1,
  "profile": "cargo-baseline-v1",
  "catalogDigest": "sha256:<64-lowercase-hex-characters>",
  "helperContractEpoch": 1,
  "expectedHelperVersion": "0.10.20",
  "expectedHelperDigest": "sha256:<64-lowercase-hex-characters>",
  "dueFactKinds": ["cargo_execution_surface.v1"]
}
```

The lifetime is at most five minutes, issuance can be at most 60 seconds in
the future, and `dueFactKinds` is a non-empty unique subset of:

- `cargo_android_corroboration.v1`
- `cargo_execution_surface.v1`
- `cargo_control_egress.v1`

The catalog digest is SHA-256 over the exact checked-in bytes of
[`../contracts/cargo-baseline-v1.json`](../contracts/cargo-baseline-v1.json).
Unknown or malformed data, a stale authorization, an epoch/catalog/version
mismatch, or a mismatch with the bounded streaming hash of `/proc/self/exe`
disables capture without affecting customer execution.

## Collection boundary

Android corroboration follows AOSP's serialized `property_info` routing and
current property-area trie. It opens only `property_info` and up to four exact
context files with `O_NOFOLLOW`; it never enumerates `/dev/__properties__`.
Each file is capped at 1 MiB and the whole read is capped at 4 MiB. Only the
nine catalog fields can be serialized, each as `observed`, `not_present`,
`permission_denied`, `surface_hidden`, `unsupported`, or `parse_error`.

Execution facts contain only the compile-time architecture/word size, page
size, kernel major/minor ABI, `no_new_privs`, the closed seccomp class, and
whether effective capabilities are zero. Raw kernel labels and capability
bitmasks are discarded.

Controlled egress derives the fixed
`GET /api/jobs/processor-facts/egress` URL from authenticated `slipwayUrl`.
One DNS resolution feeds concurrent one-attempt IPv4 and IPv6 HTTPS requests;
the original hostname remains the TLS/SNI authority. No hostname, address,
answer, header, peer, interface, route, proxy setting, cookie, redirect, or
credential can enter the result.

## Signed result

The helper canonically orders only the due facts, hashes their canonical JSON,
and signs `proof.liskov.processor-fact-result.v1` with the deployment Ed25519
bridge key. The unsigned signature input contains:

- authorization id and challenge;
- deployment, job, processor, and runtime-instance binding;
- profile, catalog digest, helper contract epoch, running package version, and
  verified executable digest;
- capture start/completion timestamps; and
- typed facts plus their `sha256:` digest.

The object contains no origin, organization, application identity, customer
value, or inferred hardware name. The canonical signed body is capped at
16 KiB and posted byte-identically at most twice to the fixed
`POST /api/jobs/processor-facts` endpoint. Each attempt is capped at five
seconds and a 4 KiB response. No retry starts after authorization expiry.

The detached worker starts immediately before the first customer-process
spawn, after access setup, and is never restarted with the customer. Spawn,
panic, collection, signing, timeout, and delivery failure are silent and cannot
change customer startup, signals, restarts, exit status, or supervisor wait
behavior.

`liskov-fact-probe` is a feature-gated, non-release binary used only by CI to
exercise observed, hidden, denied, and malformed AArch64 property fixtures
under QEMU/PRoot without external networking.
