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

## GitHub Actions runner harness

Run this local evidence harness for EPIC-20260822-u36q from the repository:

```sh
scripts/test-actions-runner-qemu-proot.sh
```

It verifies the official `actions/runner` Linux ARM64 v2.338.2 archive against
the SHA-256 pinned in the host script before starting a guest. The verified
archive is cached beside the rootfs at `.cache/qemu-proot/<digest>.tar.gz`;
`--runner-archive FILE` selects a local copy, subject to the same check. A
failed digest check refuses before extraction or guest startup. The harness
stages the archive and guest script in a temporary read-only workspace and
extracts a fresh, unpatched runner in a writable guest directory, including
`_diag` and `_work`. Guest cleanup runs through PRoot; host cleanup removes
only the host-created stage. No runner or rootfs modification is retained.

Each offline run inventories missing shared libraries with `ldd` across the
Listener, Worker, PluginHost, native .NET libraries and bundled Node binaries,
prints `/etc/os-release`, `uname -m` and `HOME`, and records the .NET environment
adjustment. It calls `bin/Runner.Listener` directly for both `--version` and
`run` with deliberately malformed JIT input. The latter must fail with a
Base64 parsing error and a non-signal exit status; a missing library, .NET
startup error, timeout, successful malformed run or identical outputs fails
the proof. The host compares both profiles' needs, version and refusal
summaries. Runner shell wrappers are not used: `run.sh` can hide Listener
failures, and its uid-0 guard needs `RUNNER_ALLOW_RUNASROOT=1` under PRoot.

Observed on p620 on 2026-11-14 with the pinned
`liskov-runtime-image-debian-trixie-aarch64` v0.1.0-rc.12 rootfs:

- `/etc/os-release` was present: Debian GNU/Linux 13 (trixie), version 13.6.
- `uname -m` was `aarch64`; `HOME` was `/root`.
- ICU was absent. `DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1` allowed .NET to
  start without adding libraries to the image.
- `ldd` reported `liblttng-ust.so.0` missing from the optional .NET trace
  provider. Neither the version nor malformed-JIT control required it.
- Both `processor-like` and `netlink-denied` produced the same summary:

```text
needs: missing-libraries=liblttng-ust.so.0 environment=DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1
version: 2.338.2 status=0
refusal: malformed-JIT Base-64 parsing status=1
```

The runner's refusal was: “The input is not a valid Base-64 string as it
contains a non-base 64 character, more than two padding characters, or an
illegal character among the padding characters.” No PRoot capability or
QEMU failure was observed for these controls. They prove startup and JIT
parsing; GitHub registration, executing a job, networking under a job load
and a real Cargo processor remain BKLG-20260822-ujy1's live evidence.
Image dependency changes belong to BKLG-20260822-z07p.

For the authorized operator's single-job live run, supply the encoded JIT
configuration in a regular, non-symlink host file of mode 0600:

```sh
scripts/test-actions-runner-qemu-proot.sh --jitconfig-file /private/runner-jitconfig
scripts/test-actions-runner-qemu-proot.sh --profile netlink-denied \
  --jitconfig-file /private/another-single-use-jitconfig
```

The host rejects other modes before starting a guest and copies the file to
its temporary stage with mode 0600. The guest reads it into the Listener's
`ACTIONS_RUNNER_INPUT_JITCONFIG` environment input; no argv contains it. It
runs `bin/Runner.Listener run --once` and prints elapsed wall-clock seconds
from Listener start to `Listening for Jobs`, from start to job completion,
and the Listener exit status. Raw live runner output is consumed privately;
only those fixed timing/status markers are printed. Missing listening or
completion markers, or a nonzero Listener exit, fail the live run. The
disposable guest owns diagnostics and generated runner credentials; keep
the source JIT file private and discard it after use. Live mode was not run
with credentials for this packet. This on-demand harness is not added to CI.
