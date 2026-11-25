# Local QEMU/PRoot tool image

This Docker build context supplies the implementation behind
`scripts/run-qemu-proot-runtime.sh`.

The PRoot executable is built from the exact clean Termux PRoot tag underlying
the Acurast Processor 1.27.0-rc1 APK readback:

- source: `termux/proot` commit `58aad2cb1c36ea6af7b32d76ccd5bf8d0a967939`
- tag: `v5.1.107.72`
- source archive SHA-256:
  `0e132e306214adba900479d3262058f179577856f375d786d3e062498ca957fd`
- Android ashmem UAPI compatibility header: generated Android-L header from
  AOSP commit `797351fd3bbb8fe517afafdd5095fd740387e7a4`, SHA-256
  `1806e49478167732a5511c87a229b5ff1df4bc4d26fbaf5282df313dab0df974`;
  the build prepends Debian's required `linux/types.h` include
- host compiler/linker: Debian Bookworm Clang + LLD (the revision's embedded
  loader requires LLD's `--rosegment` option)
- license: GPL-2.0-or-later; copied into the local tool image at
  `/usr/share/licenses/termux-proot/COPYING`

The APK binary identifies itself as `v5.1.107.72-dirty` and additionally owns
an Acurast-specific outbound-connect interceptor. That dirty patch is not
present in public Termux PRoot and is not reconstructed here. This tool matches
the public base version and command-line extensions, then exposes explicit
local fault profiles without claiming to reproduce the Android-only patch.

`scripts/smoke-qemu-proot.sh <release-helper> [static-lib-test-executable]`
keeps the release binary's version and missing-bridge refusal separate from
an offline source/ABI handoff proof. The optional executable is Cargo's existing
AArch64 library test binary, built from the same candidate source. Both emulator
profiles run the production supervisor setup and real diagnostic reporter with
offline Bridge/HTTP fixtures: an invalid inherited Android TMPDIR cannot redirect
helper storage, the real child writes an advertisement through the supplied
private paths, and canonical request bytes reach the signing seam. The direct
custody tests also exercise parent/leaf replacement, refusal, restart, and
cleanup. This fixture is test-only; it adds no release-helper bootstrap bypass
and does not prove real bridge cryptography, Acurast connectivity, or peer sync.

The tool image also builds static AArch64 linux-user QEMU 9.2.0 from the
upstream release archive, SHA-256
`f859f0bc65e1f533d040bbe8c92bcfecee5af2c921a6687c652fb44d089bd894`.
Its detached archive signature was verified with the release-manager key
`CEACC9E15534EBABB82D3FA03353C9CEF108B584`, named by qemu.org/download.
Bookworm QEMU 7.2 returns EINVAL for the supervisor's existing
PR_GET_CHILD_SUBREAPER/PR_SET_CHILD_SUBREAPER calls; upstream 9.2 implements
both. This emulator companion lets the offline fixture exercise the real
process authority and child handoff. It does not change the deployed helper's
syscall policy, the PRoot base, the pinned guest image, or the fault profiles.

## GitHub Actions runner evidence

Run the local evidence harness on demand (it is deliberately outside CI):

```sh
scripts/test-actions-runner-qemu-proot.sh
scripts/test-actions-runner-harness.sh
```

The first command downloads the official `actions/runner` linux-arm64
`2.338.2` archive (about 140 MB), verifies SHA-256
`670adb2f268fe21dcbb58b3db0e0aa9d5b3bddfe2c651481336e561ff86de945`, and
caches it beside the rootfs at `.cache/qemu-proot/<digest>.tar.gz`. Every run
verifies its staged archive before starting a guest. `--runner-archive FILE`
uses a local copy under the same pin. The second command tests digest and
credential-file refusals offline, asserting that Docker is never invoked.

Each profile gets a fresh writable runner directory inside the disposable
guest; the archive and guest script arrive through a read-only workspace. No
runner file is patched. The guest reports OS identity, architecture, HOME,
unresolved native-library dependencies and required .NET environment, then
runs `bin/Runner.Listener --version` and `bin/Runner.Listener run` with a
deliberately invalid Base64 JIT configuration. The host compares the structured
summaries. A timeout, signal, wrong version, identical version/refusal output,
host-loader failure, or refusal before managed Base64 parsing fails the proof.

Observed on p620, 2026-11-15, with the pinned `v0.1.0-rc.12` rootfs and QEMU
9.2.0 / Termux PRoot `v5.1.107.72`:

- `/etc/os-release` is present: Debian GNU/Linux 13 (trixie), full version
  13.6; `uname -m` is `aarch64`, and `HOME` is `/root`.
- ICU is absent. The guest supplies `DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1`;
  the invariant mode is a measured startup requirement, not an image change.
- `ldd` reports `liblttng-ust.so.0` missing. It does not prevent the tested
  version and managed JIT-refusal paths from running. These observations are
  inputs to the runner-image work (BKLG-20260822-z07p).
- Both `processor-like` and `netlink-denied` return version `2.338.2` with
  status 0 and the runner's malformed Base64 refusal with status 1. Neither
  profile exposed a PRoot capability blocker in these startup checks.

Both profiles produce this summary:

```text
runner-summary: version=2.338.2 version_status=0 refusal=malformed-base64 refusal_status=1 missing=liblttng-ust.so.0 invariant=1
```

This proves local .NET startup and option parsing. It does not register a
runner, execute a GitHub job, test dependency downloads, or establish real
processor compatibility. Those remain BKLG-20260822-ujy1's live proof.

For that separately authorized proof, supply a nonempty regular host file of
mode **0600** containing the encoded JIT configuration (not a GitHub API JSON
response):

```sh
scripts/test-actions-runner-qemu-proot.sh --jitconfig-file /private/jitconfig
scripts/test-actions-runner-qemu-proot.sh --profile netlink-denied \
  --jitconfig-file /private/another-single-use-jitconfig
```

Live mode uses one profile (default `processor-like`) and runs the Listener
directly once, with a one-hour limit. The guest reads the private staged file
into `ACTIONS_RUNNER_INPUT_JITCONFIG`; the value never appears in argv or
harness output. The runner's raw output and diagnostic files stay inside the
disposable guest. Only fixed readiness/completion events and exit status are
printed: elapsed wall-clock milliseconds from Listener launch to `Listening
for Jobs` and to job completion. Missing events or a nonzero Listener exit
fail the harness. A completed job can itself have failed; consult GitHub for
its result. Temporary host credentials and guest state are removed on exit;
the original host JIT file remains the operator's responsibility. No shell
wrapper is used, so the wrapper's uid-0 check and exit-status mapping cannot
masquerade as managed-runner evidence.

## Offline traversal scenario

Build and run the existing fact probe on the host:

```sh
cargo build --locked --features fact-probe --bin liskov-fact-probe
target/debug/liskov-fact-probe --traversal-scenario < tools/qemu-proot/traversal-scenario-v1.json
```

The probe reads one UTF-8 JSON object from stdin through EOF, including
when stdin is redirected from a file. The complete input is limited to
256 bytes. Version 1 accepts exactly two fields:

```json
{"version":1,"scenario":"traversal-smoke"}
```

Missing or duplicate fields, unknown versions or scenarios, extra fields,
trailing values and oversized inputs fail before any fixture socket opens.
The fixture owns its loopback endpoints and picks their ports. The request
cannot supply addresses, grants, clocks or gateway configuration. There is
no scenario command on `liskov-runtime-contact`. The fact probe's no-argument
smoke also runs this scenario and prints the existing status line.

The versioned [transcript](traversal-transcript-v1.json) is one compact JSON
line with the correlated UDP mapping and filtering classifications, the
PCP UDP baseline, create, verification, finite lease and confirmed delete,
and the separately corroborated pair direct and relay results. The prober-side
fixtures check the actual UDP source tuples, the two-socket behaviour trace
and the router's packet-derived lease state. The transcript omits addresses,
ports, secrets, proofs and timing. It describes these loopback fixtures.

From a clean checkout, run `scripts/test-traversal-scenario.sh` with the
AArch64 musl Rust target and C toolchain, Docker, and `readelf` available.
The script builds the host and static guest binaries from that checkout.
It checks that the normal runtime helper refuses the scenario argument, runs
the same request on the host and on both maintained QEMU/PRoot profiles,
and compares their stdout byte for byte. The emulator prints checksum
verification to stderr. Run artifacts are cleaned on exit.
A successful run writes `candidate-manifest.json` and `transcript.json` under
`target/traversal-evidence/<source-sha>/`. The manifest records the source SHA,
protocol version, scenario, entrypoint and SHA-256 digests of the input,
transcript and each exercised helper and fact-probe binary.

### Version 2 external loopback fixture

Build the host binary with the command above, and spawn it as
`target/debug/liskov-fact-probe --traversal-external`. For a static ARM64
candidate, build with the AArch64 musl target.

```sh
cargo build --release --locked --target aarch64-unknown-linux-musl --features fact-probe --bin liskov-fact-probe
```

Connect the child's stdin and stdout to the fixture. Send a UTF-8 request as
one newline-terminated JSON object of at most 65,536 bytes before the newline.
Objects have closed fields and reject duplicate keys and trailing values.
Every request includes the following fields.

| Field | Value |
| --- | --- |
| `version`, `scenario` | `2`, `"external-loopback"` |
| `collector` | `"udp-behaviour"`, `"mapping"`, or `"pair"` |
| `originMs` | Fixture time in Unix milliseconds at collector start. The probe adds monotonic elapsed time. |
| `grant` | `capability` is the fixture-minted v1 traversal capability object with `domain`, `descriptor` and `mac`. Supply its independently bound `artifactDigest`, `claimAuthorityDigest` and the fixture job's `jobExpiresAtMs`. |
| `endpoints` | Collector-specific object described below. Socket tuples are JSON strings with a numeric IP and a nonzero port, for example `"127.0.0.1:5000"` or `"[::1]:5000"`. |

Mint the descriptor for the selected collector with helper version
`cargo-helper-traversal-1` and helper digest `sha256:` followed by 64
`3` characters (the probe's `FIXTURE_HELPER`). The artifact digest is the
fixture's separate artifact binding. The grant and fixture job must leave
room for the chosen experiment including cleanup, plus the existing
40-second delivery reserve. This channel supplies authenticated test
inputs, so the probe checks grant shape and bindings while the fixture
holds and verifies its capability MAC key.

- **UDP behaviour** takes an enrolled nonzero `session` of 32 lowercase hexadecimal digits
  and `endpoints` with `revision` (the descriptor endpoint revision), `ap`,
  and optional `aq` and `bp`. Each endpoint has `address`,
  `mappingQualified`, and `filteringQualified`. The existing behaviour
  collector's LNT1 comparison requires IPv4 topology. It binds one socket
  for filtering and a second socket for mapping.
- **Mapping** takes `method` (`"pcp"` or `"nat-pmp"`), `transport` (`"udp"`),
  `signerSeed` (64 lowercase hex digits for a 32-byte Ed25519 seed), and
  `consent` with `consentReference`, `processorAllowlistDigest`, and
  `exclusiveReservationDigest`. Mint the same consent into the capability,
  scoped to this method. The reservation digest binds the fixture's
  synthetic gateway. Set `endpoints.router` to the router's UDP tuple,
  `pathSource` to the IPv4 address that sends dialbacks, and
  `observedAddress` to the IPv4 address reported by fixture control. Supply
  `externalAddress` for NAT-PMP when discovery established an address.
  PCP uses the external address in its MAP response. The synthetic
  gateway and client are `10.0.0.1` and `10.0.0.2` in the collector's
  route and router protocol. Socket traffic stays on the loopback router
  and listener. The fixture translates each requested dialback port to
  its loopback destination and echoes through the probe's listener.
- **Pair** takes `signerSeed` in the same format, and `endpoints` with the
  `coordinator` UDP tuple and `revision`. Mint one capability per role,
  bind its participant to that role's seed-derived `0x`-prefixed Ed25519
  public key, and pass each capability to a separate process. Both roles
  use the same pair intent. The probe uses its registration socket for
  direct punching and relay control.

Every fixture endpoint is in `127.0.0.0/8` or is `::1`. Behaviour and pair
can name an optional `natIngress` loopback UDP tuple. Framed endpoints,
including pair candidates returned by the fixture, must use that ingress's
address family. The probe sends framed datagrams to the ingress, and
accepts framed replies only from its exact tuple. A frame starts with
`0x01` and four IPv4 address bytes or `0x02` and sixteen IPv6 address bytes,
then a two-byte big-endian port and up to 512 body bytes. Outbound frames
carry the destination. Inbound frames carry the source. Malformed frames
and frames from other sources are discarded. Mapping router and dialback
traffic is unframed.

For pair and mapping, each outbound control line has the shape
`{"type":"control","path":"/v1/traversal/…","body":"<base64>"}`. The fixture
replies in order with `{"type":"response","status":200,"body":"<base64>"}`,
using a numeric 16-bit status and standard padded Base64 of the exact
body bytes. Paths are `/v1/traversal/pair/enroll`,
`/v1/traversal/pair/control`, `/v1/traversal/path/check`, and
`/v1/traversal/path/receipt`. On a path check, send the 32-byte challenge
and wait for its echo before returning a successful observation. The
receipt request includes that observation and its `deviceSignature` over
the canonical traversal transcript. Return the corresponding receipt
with the identical transcript and signature. This control channel uses
stdio and opens no HTTP or TCP connections.

The final line is a `type: "transcript"` record with `version: 2`, the
`collector` name, `result`, `refusal` (a closed code or null), and
`sockets`. The result is the collector's signed `NetworkTraversalV1` for
pair, classifications with reasons, comparisons and datagram count for
behaviour, or the mapping run's discovery, stop, totals and per-method
baseline, create, lease, verification, cleanup, stop and `expiryUnknown`.
The socket ledger lists `index` (zero-based open order), `seam`
(`behaviour`, `pair`, `mapping-listener`, or `router-client`), `local`,
`sentDatagrams`, `sentBytes`, `receivedDatagrams`, and `receivedBytes`.
Counts describe actual UDP I/O, including framing bytes and dropped
incoming datagrams. Socket rows carry only loopback tuples and counters.
The transcript carries no signer seed or raw proof secret.

SIGTERM cancels ordinary work and allows the mapping lifecycle to send
its owned delete. Keep the fixture channels open to receive the final
transcript and answer cleanup on the router. A malformed or incomplete
request, including cancellation before the terminating newline, emits
a closed refusal code on stderr, no stdout record, and a nonzero exit.
