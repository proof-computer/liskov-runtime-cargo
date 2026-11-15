#!/usr/bin/env bash
# Offline regression checks: invalid inputs must fail before Docker or download.
set -euo pipefail
[[ $# -eq 0 || ( $# -eq 1 && $1 == --guest ) ]] || { echo 'usage: test-actions-runner-harness.sh [--guest]' >&2; exit 2; }
repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
harness="${repository_root}/scripts/test-actions-runner-qemu-proot.sh"
stage=$(mktemp -d "${TMPDIR:-/tmp}/liskov-actions-inputs.XXXXXX")
trap 'rm -rf -- "${stage}"' EXIT
mkdir "${stage}/bin"
cat >"${stage}/bin/docker" <<'EOF'
#!/bin/sh
touch "${LISKOV_TEST_GUEST_MARKER}"
exit 99
EOF
cp "${stage}/bin/docker" "${stage}/bin/curl"
chmod 0755 "${stage}/bin/"*
export LISKOV_TEST_GUEST_MARKER="${stage}/guest-started"

printf 'corrupted runner archive\n' >"${stage}/corrupt.tar.gz"
expected=$(sed -n 's/^runner_sha256=//p' "${harness}")
actual=$(sha256sum "${stage}/corrupt.tar.gz")
[[ ${#expected} -eq 64 && ${actual%% *} != "${expected}" ]]
expect_refusal() {
  local expected_message=$1
  shift
  local status=0
  PATH="${stage}/bin:${PATH}" "${harness}" "$@" >"${stage}/output" 2>&1 || status=$?
  [[ ${status} -gt 0 && ${status} -ne 99 ]] || { cat "${stage}/output"; exit 1; }
  grep -Fq -- "${expected_message}" "${stage}/output"
  [[ ! -e "${LISKOV_TEST_GUEST_MARKER}" ]]
}
expect_refusal 'SHA-256 mismatch' --runner-archive "${stage}/corrupt.tar.gz"
printf 'not-a-real-credential\n' >"${stage}/jitconfig"
for mode in 0644 0400 0666; do
  chmod "${mode}" "${stage}/jitconfig"
  expect_refusal 'mode-0600 regular file' --jitconfig-file "${stage}/jitconfig"
done
chmod 0600 "${stage}/jitconfig"
expect_refusal 'SHA-256 mismatch' --jitconfig-file "${stage}/jitconfig" --runner-archive "${stage}/corrupt.tar.gz"
chmod 0600 "${stage}/jitconfig"
: >"${stage}/jitconfig"
expect_refusal 'mode-0600 regular file' --jitconfig-file "${stage}/jitconfig"
expect_refusal 'requires a value' --jitconfig-file
expect_refusal 'unsupported profile' --profile invalid
expect_refusal '--profile requires --jitconfig-file' --profile netlink-denied
echo 'Actions runner harness input refusals passed without starting a guest or download'

if [[ ${1:-} == --guest ]]; then
  # Exercise the real live-output reader without GitHub or a real credential.
  # This test adapter crosses the guest archive seam; the production host's
  # digest check above prevents this fixture from being used as a real runner.
  mkdir -p "${stage}/fixture/bin" "${stage}/fixture/externals"
  cat >"${stage}/fixture/bin/Runner.Listener" <<'EOF'
#!/bin/bash
set -eu
if [[ $1 == --version ]]; then
  echo fixture-version
  exit 0
fi
[[ $1 == run && $# -eq 1 && ${ACTIONS_RUNNER_INPUT_JITCONFIG} == fixture-secret-no-network ]]
echo "raw-output-must-be-hidden: ${ACTIONS_RUNNER_INPUT_JITCONFIG}"
echo '2026-11-15 00:00:00Z: Listening for Jobs'
echo '2026-11-15 00:00:00Z: Job fixture completed with result: Succeeded'
EOF
  chmod 0755 "${stage}/fixture/bin/Runner.Listener"
  tar -czf "${stage}/runner.tar.gz" -C "${stage}/fixture" bin externals
  printf 'fixture-secret-no-network\n' >"${stage}/jitconfig"
  chmod 0600 "${stage}/jitconfig"
  install -m 0755 "${repository_root}/tools/qemu-proot/actions-runner-guest.sh" "${stage}/guest.sh"
  "${repository_root}/scripts/run-qemu-proot-runtime.sh" --workspace "${stage}" -- \
    /bin/bash /workspace/guest.sh fixture-version processor-like live >"${stage}/live-output" 2>&1
  grep -Eq '^listening-seconds=[0-9]+$' "${stage}/live-output"
  grep -Eq '^job-completion-seconds=[0-9]+$' "${stage}/live-output"
  grep -Fxq 'live-runner-status=0' "${stage}/live-output"
  ! grep -Eq 'fixture-secret-no-network|raw-output-must-be-hidden' "${stage}/live-output"
  echo 'Actions runner guest fixture passed: environment input, timing markers and raw-output redaction'
fi
