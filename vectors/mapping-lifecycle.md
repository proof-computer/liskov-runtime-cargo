# Dormant mapping lifecycle fixtures

BKLG-20261014-95bj; ADR-0234. No new wire contract or activation.

`src/network_traversal/lifecycle/tests.rs` composes the real PCP, NAT-PMP and
UPnP codecs under one injected monotonic clock, router transport, listener and
path-control seam. It uses the unchanged shared traversal vectors and UPnP XML
fixtures. Prober source: `ecd9b478d4700d0cb55c761ec0dbf1adc068344f` (dc8k).

The lifecycle consumes one authenticated-bootstrap session. The upstream API
remains the consent/issuance owner: it consumes consent once and requires an
explicit operator resolution before fresh consent after unknown creation or
cleanup. The native helper has no MAC key, consent database or second issuer.
No normal-helper caller invokes this collector. The future activation caller
must supply the independently authenticated bootstrap/consent bindings, the
selected owned-fixture gateway, and discovery traffic already spent in that
same run. Every I/O seam must enforce its absolute deadline. Router requests
and path check/receipt calls share the control allowance; UDP router requests
and challenge echoes additionally spend datagrams. Counts are charged before
I/O with no refunds; cleanup counts and time cannot fund ordinary operations.

Each method/transport entry owns a fresh listener. Baseline precedes create;
cleanup precedes the next entry. TCP and UDP are distinct entries. A combined
plan that exceeds time, packet, control or four-dialback ceilings runs only its
first entry and explicitly records the rest as deferred to separately consented
profiles. It never rearms consent. PCP uses its correlated returned external
address; NAT-PMP/UPnP require a separately discovered address. Missing or differing
addresses produce unverifiable_endpoint without a path request. No verifier
request contains a destination address; the prober chooses its observed peer.

A path observation must bind the exact descriptor/run, expiry, method, phase,
transport, family and echoed challenge before the signer/receipt seam runs.
These local summaries do not manufacture signed receipts or admitted results.
The activation caller must use bounded authenticated control, sign only the
validated canonical transcript through the existing bridge, and validate that
the receipt preserves it. Device signature verification remains with the API.
The native TCP/UDP listener echoes only one 32-byte challenge per phase from the pinned
prober source; localhost tests exercise both real transport boundaries.

Success, verification failure, cancellation, job expiry and graceful shutdown
converge on explicit owned deletion within the original reserve. If no deletion
could be sent before the absolute deadline, a known finite handle remains
lease_expiry_pending. A failed deletion is delete_failed, with expiry_unknown
retained independently when its response was lost. Unknown creation has no
invented handle: creation_outcome_unknown and expiry_unknown survive, and no
later method runs. Pre-existing/static mappings are never deleted merely for
having a zero or overlong lease.

The crash fixture interrupts after create and proves that dropping the listener
is not router cleanup. There is no native post-crash report: the issued run
without a terminal result remains outcome unknown at the API owner. A requested
finite lifetime is never interpreted here as verified expiry. Only the
independent owned-gateway fixture can establish finite enforcement; descriptors
without that attestation are refused before any effects. No renewal, permanent
fallback, create retry, live network probe or consumer-router claim is made.
