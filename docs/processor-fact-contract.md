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
the future, and for `cargo-baseline-v1` `dueFactKinds` is a non-empty unique
subset of:

- `cargo_android_corroboration.v1`
- `cargo_execution_surface.v1`
- `cargo_control_egress.v1`

A `coverage-hardware-v1` grant names exactly `["coverage_hardware_raw.v1"]`
(see [Coverage hardware profile](#coverage-hardware-profile)). A grant that
mixes the two profiles' kinds, or names an unknown profile, is not a grant.

The catalog digest is SHA-256 over the exact checked-in bytes of the named
profile's catalog:
[`../contracts/cargo-baseline-v1.json`](../contracts/cargo-baseline-v1.json) or
[`../contracts/coverage-hardware-v1.json`](../contracts/coverage-hardware-v1.json).
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
16 KiB; a body that cannot fit once signed is never signed. It is posted byte-identically at most twice to the fixed
`POST /api/jobs/processor-facts` endpoint. Each attempt is capped at five
seconds and a 4 KiB response. No retry starts after authorization expiry.

`vectors/processor-fact-result-v1.json` pins the signature input. It holds one
unsigned body and the exact canonical bytes that body signs, and the same file
is checked into `liskov-rs` at
`crates/slipway-executor-contracts/vectors/`. Each repository rebuilds the body
from its own types and compares the canonical **string**, so either side
drifting fails its own test. The vector carries no `signature`: the signature
is not part of its own input. A device's egress fact is `{ipv4, ipv6}` and
nothing else; the domain, profile, helper version and capture time around a
stored reading are the server's to state, not the helper's.

The detached worker starts immediately before the first customer-process
spawn, after access setup, and is never restarted with the customer. Spawn,
panic, collection, signing, timeout, and delivery failure are silent and cannot
change customer startup, signals, restarts, exit status, or supervisor wait
behavior.

`liskov-fact-probe` is a feature-gated, non-release binary used only by CI to
exercise observed, hidden, denied, and malformed AArch64 property fixtures
under QEMU/PRoot without external networking. It also takes one live raw
hardware reading through the real file and syscall source, checks that the
kernel, guest uid, `MemTotal` and guest-root readings are observed, and sends
it nowhere.

## Coverage hardware profile

`coverage-hardware-v1` (BKLG-20260923-9bhd; ADR-0079 probe amendment;
Q-20260923-z2uc) is a separate, coverage-only profile on the same envelope,
domains, endpoint, five-minute lifetime and 16 KiB cap. Its one kind,
`coverage_hardware_raw.v1`, is the closed raw hardware reading a platform
coverage probe takes. The server mints it only for a canonical
`PlatformCoverage` bootstrap, an allowed application and a pinned helper
version/digest; the helper neither receives nor reports that origin. An
ADR-0072 coverage grant (`factAuthorization`) never authorizes it, and a
baseline grant never reads it. The baseline catalog, its digest and every
baseline and ADR-0072 vector are unchanged.

`liskov-rs` owns the contract. These files are byte copies from its merge
commit `9297d1e928fe62fe5df6b83a9103992436eb21bf` (PR #1097,
BKLG-20260923-mjay), and offline tests pin their SHA-256:

| File | SHA-256 |
| --- | --- |
| `contracts/coverage-hardware-v1.json` (its `catalogDigest`) | `f39caf2456a8d4cbca429f06c5b69d014c47dc76cdcbb0c94bd508a04b89ccb5` |
| `vectors/processor-fact-coverage-hardware-v1.json` | `f35eb94ee1cdee20cb7245cb3e14a708b254c06927d2ca2ab8a742707e375959` |
| `vectors/processor-hardware-raw-v1.json` | `345099f5cad2e7d8ae95ad66412aa6cbfe6a9bae9f20c2ede4b8b9ab0486961b` |

A fixture tree shaped like the Motorola job 174098 readback reproduces the
payload vector exactly, and the unsigned result built from it reproduces the
result vector's canonical signing bytes.

The collector is Rust in the helper, reading through a bounded file and
syscall seam; no shell runs. It opens only:

- `uname` release and machine; `getuid`; `Uid:` and `CapEff:` from
  `/proc/self/status` (the capability bitset is reduced to `none`/`nonzero`);
- controller names from `/proc/self/cgroup`, never their paths;
- `/sys/devices/system/cpu/cpufreq/policyN/{related_cpus, cpuinfo_min_freq,
  cpuinfo_max_freq, scaling_available_frequencies, scaling_governor,
  scaling_driver}`, and for the policy's first cpu `regs/identification/midr_el1`
  and `cpu_capacity`;
- `/sys/devices/system/cpu/cpuN/cache/indexM/{level, type, shared_cpu_list,
  size}`, deduplicated and ordered from each core's private caches outward;
- the twenty closed `/proc/meminfo` lines;
- `/sys/devices/soc0/{family, soc_id}` and
  `/sys/class/kgsl/kgsl-3d0/{gpu_model, max_gpuclk}`;
- `statvfs` of the guest root; and
- `/sys/class/thermal/thermal_zoneN/{type, temp}` in index order.

`/proc/self/mountinfo` is parsed in memory to find two entries: the guest
root's, by the device `stat("/")` reports (under PRoot the kernel's `/` is
Android's system image, not the volume the guest sits on), and `/data`'s, by
mount point. Only the filesystem type (a fuse subtype becomes `fuse`) and the
`inlinecrypt` and `discard` flags leave the parser; no mount source, mount
point or other option can be represented. Serials, `soc0/machine`, current
frequencies, `/proc/mounts`, `/proc/net`, `/dev` and property files are never
opened.

Every file stops at a byte cap (one page for a sysfs attribute) and every list
at its catalog cap: 16 cgroup controllers, 16 policies, 32 frequencies, 64
caches, 128 thermal zones. A missing file is `not_present` and a refused open
is `permission_denied`; they never collapse, and a zero is a value. A thermal
temperature that reads empty or fails is `unread`, and `vbat` stays a raw zone
reading. No retail model, part number or storage interface is inferred, and a
value the server's grammar would refuse (a path, a package name) is
`parse_error` instead of being sent.

A read failure changes only its own reading. It never changes the customer
command, the probe's exit or the baseline facts. A stale, wrong-profile,
wrong-catalog or wrong-helper grant produces no raw read, no signature and no
network call, and a reading too large for the 16 KiB body is never signed or
sent.
