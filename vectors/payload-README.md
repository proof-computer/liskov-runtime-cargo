# Cargo payload delivery v1 fixtures

BKLG-20261013-bw93 freezes pure contracts from ADR-0230 and ADR-0232.
These fixtures enable no route, storage access, manifest version or capability.

`slipway-policy-contracts::payload` owns the descriptor. Runtime request and
internal authorization types live in `slipway-executor-contracts::payload_delivery`.
The archive and descriptor have distinct SHA-256 identities; bind both in the
existing immutable Application artifact-version record. The descriptor is a
companion object outside the archive. The archive contains only `bin` and
`bin/app`, with fixed USTAR metadata, gzip mtime zero and no descriptor/self hash.
Metadata validation does not inspect uploaded bytes or confer provenance,
platform support or execution permission. Those checks retain their existing owners.

Canonical bytes are compact UTF-8 JSON with the exact declaration order in the
Rust types (shown in `canonicalUtf8` / `messageUtf8`). Serialize each nested type
in that order, with no omitted fields, whitespace or newline; use explicit null
for launch-only `workload`. ASCII identifiers, paths and provenance avoid
language-specific Unicode escaping. All numeric fields admitted to canonical
bytes fit JavaScript's safe integers. The canonical job owner supplies normalized
origin kind/key and a canonical decimal u128 sequence **string**, including zero.
Do not interpret a request's origin key as a supplied signing public key.

The envelope has `request` and lowercase-hex Ed25519 `signature`. Sign only the
canonical request bytes, without prehashing. Use the job's chain-verified signing
key; no key is included in the envelope. The signing domain is
`proof.liskov.payload-download.v1`. The test-only seed is RFC 8032's public first
test seed, deliberately insecure and never usable as runtime authority.

The target is exactly `/v1/payloads/<sha256:lowercase-hex>` with method `GET`,
no query, percent encoding, slash alias, fragment or absolute URL. A missing
Range header means `{"mode":"whole"}`. Single closed inclusive ranges have
`{"mode":"bytes","start":0,"endInclusive":15}` and transport
`Range: bytes=0-15`. Reject open-ended, suffix, multipart, leading-zero,
whitespace and overflow aliases. Whole ranges reject extra fields; inverted
ranges refuse with `invalid_range`. Zero offset is legitimate; range ends must be
inside the verified object size. Resume requests choose another closed range.

Wire envelopes are at most 8192 bytes. Time is integer milliseconds with
`0 <= issuedAtMs <= nowMs < expiresAtMs` and a positive span at most 60000 ms.
The canonical authority further bounds expiry by job/entitlement expiry. Nonces
are exactly 32 bytes of lowercase hex and are consumed once by that authority;
every failed/retried transfer signs a fresh nonce. Bootstrap retry rules are
unchanged. Artifact, tenant/job/incarnation, immutable launch policy and optional
workload authorization/revision/policy bindings are distinct signed fields.

The authenticated internal authority reply carries the exact object key,
selection, identities, request digest, expiry and retained transfer reference.
It is never a public response or bearer redirect. Its edge validation cannot
replace job-signature verification, atomic replay consumption, entitlement
revocation checks or transactional storage retention. Authority unavailability
is a typed refusal. The first descriptor mode is `none`; `signer` and unknown
modes refuse. ABI tokens describe a target; the existing catalogue must prove
actual image/helper compatibility. The descriptor validator takes the configured
artifact byte ceiling from its owner (the fixture uses the existing 8 MiB
value), with no fallback or quota increase. Inventory validation caps 256 entries
and 4 GiB expansion, allows zero-byte files, rejects aliases/duplicate paths,
file-as-directory conflicts, links/devices and non-executable entrypoints.

Offline reproduction and independent signing proof:

```sh
python3 crates/slipway-executor-contracts/vectors/payload-vectors.py --check
node crates/slipway-executor-contracts/vectors/payload-cross-language.mjs
(cd crates/slipway-executor-contracts/vectors && sha256sum -c payload-fixtures.sha256)
```

Produced and checked with Python 3, cryptography 50.0.1 and Node v24.19.0
(`node:crypto`, no npm dependency). Python's ordered schema constructs deterministic
archive/descriptor/request bytes and signatures. Node independently builds the
schema order, recomputes bytes/digests, signs all three messages identically and
verifies all 31 negative request cases without stripping unknown fields from
the mutated signing bytes. Rust owner tests compare exact canonical
strings/digests and pin parser, transport, identity, size, arithmetic and expiry
refusals; the 25 negative descriptor cases also run in the policy owner target.
Rust contracts do not verify Ed25519 signatures. The future runtime verifying
authority must check these exact fixtures with `ed25519-dalek` before origin access.
The hash manifest addresses the raw fixture files; it does not hash itself.
Existing bootstrap, diagnostic and V5/V6/V7 fixtures are preserved.

## Runtime consumer provenance (BKLG-20261013-1iu2)

The files above are copied byte-for-byte from liskov-rs main
`679df762044241a4a0512428a91b5ee572f54059` (remote main readback
2026-10-13). This includes the malformed-range repair at
`e925621adb631cdd9fdbde8968aff23fcf700e20`; the terminal bw93 checkpoint's
older download-fixture digest is superseded by `payload-fixtures.sha256`.
The archive and descriptor fixture digests are unchanged. Source SHA-256:

- `slipway-executor-contracts/src/payload_delivery.rs`:
  `38010ffbbec9da7b21df77c8c32dcf92753b184320b4241c44ce4cddae08f0a7`.
- `slipway-policy-contracts/src/payload.rs`:
  `7a0dbad95abccd26f12a954365eb7165ccd7e75dcd83465be794deb0a26daeb3`.

`src/payload_protocol.rs` retains the owner's request/range/binding encodings
and validation; `descriptor.rs` retains its descriptor contract. The standalone
consumer omits the Acurast owner-crate conversion and internal edge/storage
reply types. Entitlement, replay consumption and storage retention remain in
liskov-rs. The existing library tests consume every owner negative fixture and
independently sign all three valid vectors with ring Ed25519.

Local reproduction (no network):

```sh
python3 vectors/payload-vectors.py --check
node vectors/payload-cross-language.mjs
(cd vectors && sha256sum -c payload-fixtures.sha256)
cargo test --workspace --all-features --locked
```

The runtime downloader's public local seams are `AuthenticatedPayloadContext`,
`PayloadContext::negotiate`, `PayloadHttpClient::get` and `download_payload`.
The authenticated context owner supplies the exact origin, owner binding,
canonical companion bytes/digest and configured artifact ceiling. Negotiation
compares first-contact application/job/processor/incarnation/launch-policy
bindings and refuses unknown capability, encryption, malformed descriptors,
non-origin URLs and expired authority. Only the current bridge Acurast
`kind/source` origin representation is supported by the dormant client; unknown
representations refuse rather than guessing owner normalization.

Known owner identity mismatch (review lrc-iusd, BKLG-20261013-1iu2): at the
owner source pin above, `PayloadJobRefV1::from` copies `job.origin_kind`, while
`slipway-acurast-chain::normalized_runtime_origin` emits `"Acurast"`. The
download fixture's `expectedBinding.job.originKind` is instead `"acurast"`,
which this dormant consumer retains. For the same origin key and sequence,
an owner-produced binding with `"Acurast"` therefore fails negotiation with
`PayloadError::Binding`. This is a concrete interoperability blocker, not a
claim that the production normalizer matches the fixture. The liskov-rs
payload/identity owner must settle the canonical casing and publish consistent
conversion and vectors before runtime integration. The counterexample is
escalated in the packet handoff; this consumer does not accept both spellings
or silently change the signed contract.

The signed envelope's HTTP carrier and response header names are not frozen in
bw93. `PayloadHttpClient` therefore remains an injectable transport seam until
the artifact-serving owner publishes that transport; it accepts exact envelope
bytes and the single Range value separately. Adapters must disable redirects,
automatic retries and decompression, reject duplicate headers, and bound header
and connect/read times. This packet does not add speculative server headers or
enable a runtime producer. Existing POST/bootstrap retries and exits are untouched.

Transfers start in a fresh staging sink. They resume only this invocation's
verified prefix (never trust an existing cache or sink length), hash every written
byte, bound each read to 16 KiB, and require exact raw entity length, range,
artifact and descriptor identities. Every attempt has a fresh nonce/signature;
the bounded invocation budget never resets. The writer remains the staging
owner: partial bytes are untrusted, a write/flush failure is surfaced, and only
`VerifiedPayload` after complete length/digest validation permits that owner to
continue toward atomic publication. No extraction or process handoff occurs.

If an individual request expires before the complete entity arrives while
context authorization is still valid, close that stream and resume the exact
received prefix with a fresh signed request. If the complete entity has arrived,
request expiry does not discard it: exact length/digest checks still apply.
Context authorization expiry remains a refusal during either path.
