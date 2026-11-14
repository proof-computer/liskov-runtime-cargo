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

## GitHub Actions runner

Run the local evidence harness on a Docker host:

```sh
scripts/test-actions-runner-qemu-proot.sh
scripts/test-actions-runner-qemu-proot.sh --self-test-inputs
```

The host script pins the official `actions/runner` linux-arm64 v2.338.2 archive
and SHA-256 `670adb2f268fe21dcbb58b3db0e0aa9d5b3bddfe2c651481336e561ff86de945`.
It downloads about 140 MB once and caches it by digest beside the rootfs in
`.cache/qemu-proot/`. `--runner-archive FILE` accepts a pre-downloaded copy with
the same digest. Every run verifies the staged archive before starting Docker.
The read-only workspace contains the archive and guest script; extraction,
`_diag` and `_work` live in a private writable guest directory, removed by the
guest before the container exits. No runner file is patched.

Without credentials, each profile runs `bin/Runner.Listener --version` and
`bin/Runner.Listener run` with deliberately malformed JIT input. The guest
reports `/etc/os-release`, architecture, HOME, missing native ELF dependencies
in `bin/` and `externals/`, and its globalization setting. It requires the exact
pinned version, a nonzero normal malformed-input exit and a JIT parsing error;
loader, ICU, wrapper, timeout and .NET startup failures fail the proof. The host
requires both profile summaries to agree. `--self-test-inputs` checks a known
digest mismatch and a non-0600 credential file, asserting that neither starts
Docker. `bash -n` checks both host and guest scripts. This on-demand harness is
not part of CI and does not register a runner or execute a GitHub job.

Observed on p620, 2026-11-14, using the rootfs pin above and QEMU 9.2.0:

| Observation | `processor-like` | `netlink-denied` |
| --- | --- | --- |
| Image identity | Debian 13.6 (trixie), `aarch64`, `HOME=/root` | Same |
| Missing dependency | `bin/libcoreclrtraceptprovider.so`: `liblttng-ust.so.0` | Same |
| Required environment | `DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1` (ICU absent) | Same |
| Listener `--version` | `2.338.2`, status 0 | Same |
| Malformed JIT | Base-64 parsing refusal, status 1 | Same |

Both profiles refused with: “The input is not a valid Base-64 string as it
contains a non-base 64 character, more than two padding characters, or an
illegal character among the padding characters.” The tracing provider's
missing library did not prevent these commands from starting. Installing ICU
or tracing libraries in a future runner image belongs to BKLG-20260822-z07p.
These observations prove .NET startup and local JIT parsing, not registration,
job execution, Docker/service-container support, or connectivity on a processor.
Neither profile exposed a PRoot capability failure in the exercised commands.

A person with a JIT configuration can run one real ephemeral runner:

```sh
chmod 0600 /private/path/jitconfig
scripts/test-actions-runner-qemu-proot.sh --jitconfig-file /private/path/jitconfig
scripts/test-actions-runner-qemu-proot.sh --profile netlink-denied \
  --jitconfig-file /private/path/fresh-jitconfig
```

Use a fresh JIT configuration for each run. The host requires a nonempty,
regular, nonsymlink mode-0600 file and copies it into the private stage with
mode 0600. The guest supplies `ACTIONS_RUNNER_INPUT_JITCONFIG` directly to the
Listener through its environment; the value never enters a command argument
or harness output. Runner logs stay inside the disposable guest. Output is
limited to the environment summary, start-to-`Listening for Jobs` time,
start-to-job-completion time, job runtime when observed, and final status.
A successful live result requires listening, completion and status 0. This
mode was not used for the offline proof. BKLG-20260822-ujy1 owns the live GitHub
and paid Cargo canary measurements; this harness creates no credentials.
