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
