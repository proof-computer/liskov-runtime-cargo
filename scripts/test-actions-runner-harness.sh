#!/usr/bin/env bash
# Offline refusal regressions: no Docker, downloads, or GitHub credentials.
set -euo pipefail
umask 077
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
harness="${repo_root}/scripts/test-actions-runner-qemu-proot.sh"
stage=$(mktemp -d "${TMPDIR:-/tmp}/liskov-actions-runner-guards.XXXXXX")
trap 'rm -rf -- "${stage}"' EXIT
mkdir "${stage}/bin"
# Any Docker call is a regression; the tested inputs must refuse beforehand.
cat > "${stage}/bin/docker" <<'EOF'
#!/usr/bin/env bash
touch "${LISKOV_RUNNER_GUARD_MARKER}"
exit 99
EOF
chmod 0755 "${stage}/bin/docker"
export PATH="${stage}/bin:${PATH}"
export LISKOV_RUNNER_GUARD_MARKER="${stage}/docker-called"

expect_refusal() {
  local message=$1
  shift
  if "${harness}" "$@" > "${stage}/output" 2>&1; then
    echo 'expected harness refusal' >&2
    exit 1
  fi
  grep -Fq -- "${message}" "${stage}/output"
  [[ ! -e ${LISKOV_RUNNER_GUARD_MARKER} ]]
  ! grep -Fq 'fixture-jit-value' "${stage}/output"
}

printf 'corrupted runner archive\n' > "${stage}/corrupt.tar.gz"
# Read the production pin so moving the version cannot stale the regression.
pin=$(sed -n 's/^runner_sha256=//p' "${harness}")
[[ ${pin} =~ ^[a-f0-9]{64}$ ]]
actual=$(sha256sum "${stage}/corrupt.tar.gz")
[[ ${actual%% *} != "${pin}" ]]
expect_refusal 'runner archive SHA-256 mismatch; guest was not started' \
  --runner-archive "${stage}/corrupt.tar.gz"

printf 'fixture-jit-value\n' > "${stage}/jitconfig"
for mode in 0644 0400 0660; do
  chmod "${mode}" "${stage}/jitconfig"
  expect_refusal 'mode 0600' --jitconfig-file "${stage}/jitconfig"
done
chmod 0600 "${stage}/jitconfig"
ln -s jitconfig "${stage}/jitconfig-link"
expect_refusal 'mode 0600' --jitconfig-file "${stage}/jitconfig-link"
# Mode 0600 advances to archive verification, still without exposing the secret.
expect_refusal 'runner archive SHA-256 mismatch; guest was not started' \
  --jitconfig-file "${stage}/jitconfig" --runner-archive "${stage}/corrupt.tar.gz"
expect_refusal 'unsupported profile' --profile unknown
expect_refusal '--profile is for live mode' --profile netlink-denied
echo 'Actions runner archive/credential refusal regressions passed'
