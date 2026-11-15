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

Run the local, credential-free proof with Docker:

```sh
scripts/test-actions-runner-qemu-proot.sh
scripts/test-actions-runner-harness.sh # offline input-refusal regression checks
scripts/test-actions-runner-harness.sh --guest # synthetic live-output check, no GitHub credential
```

The harness downloads the official `actions/runner` linux-arm64 v2.338.2
archive, verifies SHA-256
`670adb2f268fe21dcbb58b3db0e0aa9d5b3bddfe2c651481336e561ff86de945`, and
caches it under `.cache/qemu-proot/<sha256>.tar.gz` beside the rootfs cache.
Every use verifies the cached archive and the staged copy before guest startup.
`--runner-archive FILE` verifies an existing copy against the same pin; a
corrupted copy fails before extraction or guest execution. The rootfs pin stays
v0.1.0-rc.12, SHA-256
`0639e88db6b46cef6091acafe35dfb1b59c5e354463d969f1a9509451d118377`.
This on-demand evidence harness for EPIC-20260822-u36q is outside CI; the runner
archive alone is about 140 MB.

For each of `processor-like` and `netlink-denied`, the archive and guest script
are staged in a private temporary workspace bound read-only at `/workspace`.
The unmodified runner is extracted into a private writable directory below
`/root`, including writable `_diag` and `_work`. The guest prints OS-release
content, architecture, HOME, missing shared libraries (including .NET and
bundled Node binaries), any startup environment adjustment, the version, and
the malformed-JIT refusal and status. The harness compares both profiles'
version, missing libraries, required environment, refusal text and status. It requires
the exact pinned version with status 0, then a distinct JIT parsing refusal
with status 1–127, rejecting loader, ICU, root-wrapper and .NET host failures.
It calls `bin/Runner.Listener` directly; the runner's shell wrappers can mask
failure status. No runner file is patched and no packages are installed.

Observed on p620, 2026-11-15, with the pins above:

| Evidence | processor-like | netlink-denied |
| --- | --- | --- |
| `uname -m`, HOME | `aarch64`, `/root` | `aarch64`, `/root` |
| `/etc/os-release` | Debian GNU/Linux 13 (trixie), full version 13.6 | same |
| Missing shared library reported by `ldd` | `liblttng-ust.so.0` | same |
| Required startup environment | `DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1` | same |
| Listener `--version` | `2.338.2`, status 0 | same |
| Malformed JIT | Base-64 parsing refusal, status 1 | same |

Without invariant globalization, .NET aborts because the pinned image has no
valid ICU package. The guest retries only this diagnosed case with the .NET
invariant setting; it prints that requirement. The absent LTTng library did
not prevent version startup or JIT parsing; the dependency inventory does not
assume every optional library blocks startup. The image lane
(BKLG-20260822-z07p) owns adding dependencies to a runner rootfs.

This run proves the .NET host starts and reaches JIT parsing under both
profiles. It does not prove GitHub registration, job execution, containers or
services, job dependency downloads, or processor performance. No PRoot
capability refusal was observed in these offline checks. The live Cargo
canary and measurements belong to BKLG-20260822-ujy1.

A person with a separately authorized disposable GitHub job can run one live
JIT runner, choosing one profile per invocation:

```sh
chmod 0600 /protected/path/jitconfig
scripts/test-actions-runner-qemu-proot.sh \
  --jitconfig-file /protected/path/jitconfig --profile processor-like
# Mint a fresh single-use JIT configuration before trying netlink-denied.
```

The file contains the encoded JIT configuration, not a JSON response or shell
assignment. A missing, empty or non-0600 file is refused before downloading or
starting a guest. The harness copies it into the private stage with mode 0600;
the guest supplies `ACTIONS_RUNNER_INPUT_JITCONFIG` to the direct Listener
process. The configuration never enters argv or harness output. Raw live
output and runner diagnostics remain in disposable guest storage; only fixed
state markers, Listener exit status, and wall-clock seconds from Listener
start to `Listening for Jobs` and job completion are printed. A successful
harness exit requires both events and Listener status 0; the job's own result
is available in GitHub. Guest files are removed through PRoot and the host stage
is removed on exit. The caller retains ownership of the original credential
file and any GitHub-side registration. Live mode has not been exercised by
this packet's credential-free proof.
