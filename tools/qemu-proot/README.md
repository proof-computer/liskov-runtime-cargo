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

## Actions runner evidence

Run the local, on-demand harness from the repository root:

```sh
scripts/test-actions-runner-inputs.sh
scripts/test-actions-runner-qemu-proot.sh
```

It downloads the official `actions/runner` ARM64 v2.338.2 archive and verifies
SHA-256 `670adb2f268fe21dcbb58b3db0e0aa9d5b3bddfe2c651481336e561ff86de945`
before staging or extraction. The verified archive is cached by digest beside
the rootfs in `.cache/qemu-proot/`. `--runner-archive FILE` verifies an existing
copy with the same pin; a bad digest refuses before Docker starts. The small
input regression checks this refusal and credential-file permissions without
network access or Docker. The 140 MB runner harness is not part of CI.

For both `processor-like` and `netlink-denied`, a private temporary workspace
provides the archive and guest script read-only. The unpatched runner extracts
into writable `/root/actions-runner`, including `_diag` and `_work`, inside the
disposable guest. Each run reports `/etc/os-release`, `uname -m`, `HOME`, and
missing shared libraries from `ldd` across native ELF files in `bin/`. It then
requires `bin/Runner.Listener --version` to succeed with the pinned version,
and calls `bin/Runner.Listener run` directly with malformed JIT input. That
control must reach the runner's configuration parser and exit nonzero below
128; timeouts, signals, loader/ICU failures, wrapper refusals, and identical
version/refusal outputs fail the harness. Profile summaries must agree.

The p620 run on 2026-11-12 with rootfs v0.1.0-rc.12 observed:

- Debian GNU/Linux 13 (trixie), `DEBIAN_VERSION_FULL=13.6`, `uname -m=aarch64`,
  and `HOME=/root`.
- ICU is absent. The guest supplies
  `DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1` to start .NET without adding image
  packages. This is a feasibility setting; jobs needing culture-specific
  behavior still need ICU in a future runner image.
- `bin/libcoreclrtraceptprovider.so` lacks `liblttng-ust.so.0`. This did not
  prevent version reporting or configuration parsing; tracing remains unproved.
- The guest sets `RUNNER_ALLOW_RUNASROOT=1` for wrapper compatibility with
  PRoot's uid 0. The proof invokes the Listener directly: the runner's shell
  wrappers can hide its return status or refuse root before .NET starts.
- Runner version `2.338.2` exited 0. Malformed JIT input exited 1 with
  `The input is not a valid Base-64 string` and the runner's explanation.

The offline proof establishes startup and configuration parsing only. It does
not register a runner, execute a GitHub job, test action dependencies, or prove
real Android/Acurast capabilities. No runner file or rootfs package is patched.
The image requirements belong to BKLG-20260822-z07p; live registration and the
paid Cargo canary remain BKLG-20260822-ujy1's work for EPIC-20260822-u36q.

An operator with a real JIT configuration can run one assignment:

```sh
chmod 0600 /private/path/jitconfig
scripts/test-actions-runner-qemu-proot.sh \
  --jitconfig-file /private/path/jitconfig --profile processor-like
# Use a fresh single-use JIT configuration for the other profile.
```

The source must be a nonempty regular, nonsymlink mode-0600 file. The harness
copies it into its private stage with mode 0600 before mounting the workspace.
The guest reads it into `ACTIONS_RUNNER_INPUT_JITCONFIG`; the secret never goes
in argv or harness output. Live runner output stays in the disposable guest;
only observed readiness, job-completion and process-exit elapsed milliseconds
and status are printed. Progress is sampled every 200 ms, so reported times are
observation bounds, including emulator overhead. A live run requires readiness,
a completion message and exit 0. This credential-dependent mode was not used
for the offline proof. The harness deletes its stage, and the emulator removes
the extracted guest and private logs through the UID that created them.
