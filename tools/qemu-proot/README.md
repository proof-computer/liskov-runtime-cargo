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

Run the local, unregistered check on demand:

```sh
scripts/test-actions-runner-qemu-proot.sh --self-test
scripts/test-actions-runner-qemu-proot.sh
```

The harness pins the official [actions/runner v2.338.2 release](https://github.com/actions/runner/releases/tag/v2.338.2)
linux-arm64 archive to SHA-256
`670adb2f268fe21dcbb58b3db0e0aa9d5b3bddfe2c651481336e561ff86de945`.
It downloads once into `.cache/qemu-proot/<digest>.tar.gz` beside the rootfs
cache and verifies the digest on every use, before starting Docker. Use
`--runner-archive FILE` to verify a supplied copy; `--self-test` proves that a
corrupt copy and a JIT file with mode other than 0600 are refused before Docker.
The 140 MB download is why this evidence harness runs locally on demand rather
than in CI.

For each of `processor-like` and `netlink-denied`, the archive and guest script
are staged in a private, read-only workspace. The guest extracts an unmodified
runner into a disposable writable `/root/actions-runner.*`, including `_diag`
and `_work`. It records `ldd`'s missing libraries for native `bin` executables
and shared objects, `/etc/os-release`, `uname -m`, `HOME`, and the .NET ICU
setting. It requires `bin/Runner.Listener --version` to succeed with the pinned
version, then requires a different, nonzero malformed-JIT refusal from
`bin/Runner.Listener run`. A timeout, signal, loader failure, ICU startup
failure, or root-wrapper refusal fails the check. The host compares the two
profiles' version, refusal status, missing-library list and ICU setting.
Calling the Listener directly preserves its actual status; the upstream shell
wrappers map some failures to success and impose their own root check.

Execution on p620, 2026-11-13, with maintained rootfs `v0.1.0-rc.12`:

- `/etc/os-release` identified Debian GNU/Linux 13 (trixie), version 13.6;
  `uname -m` was `aarch64` and `HOME` was `/root`.
- ICU was absent. The harness supplied
  `DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1` without changing the image or any
  runner file. `ldd` reported `liblttng-ust.so.0` missing; that optional tracing
  dependency did not prevent the Listener from starting.
- Both profiles printed `2.338.2` with status 0 and rejected the malformed JIT
  configuration with status 1: “The input is not a valid Base-64 string”.

This proves local .NET startup and option parsing. It does not prove GitHub
registration, job execution, action dependencies, network throughput, Android
capabilities or the paid Cargo canary. No emulator capability failure was
observed in these two local controls. Image additions belong to
BKLG-20260822-z07p; live feasibility evidence belongs to BKLG-20260822-ujy1 in
EPIC-20260822-u36q.

For an authorized live run, provide a single-use JIT configuration in a regular,
non-symlink host file of mode 0600:

```sh
scripts/test-actions-runner-qemu-proot.sh \
  --jitconfig-file /protected/path/jitconfig --profile processor-like
# Repeat with a fresh JIT configuration and --profile netlink-denied.
```

The default live profile is `processor-like`. The harness copies the file into
its private stage with mode 0600. The guest supplies it through the runner's
`ACTIONS_RUNNER_INPUT_JITCONFIG` environment input, never argv. Runner logs and
`_diag` stay in the disposable guest and are deleted there; they are never
printed or copied to the host. Output contains only startup evidence, observed
wall-clock seconds from Listener start to `Listening for Jobs`, start to job
completion, listening to job completion, and final exit status. Milestones are
sampled once per second. A missing milestone or nonzero Listener exit fails
the live run. This packet did not run live mode or register a runner.
