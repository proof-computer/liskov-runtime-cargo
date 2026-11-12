#!/usr/bin/env bash
# Offline regression: invalid inputs cannot reach a download or guest startup.
set -euo pipefail
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
stage=$(mktemp -d "${TMPDIR:-/tmp}/liskov-runner-inputs.XXXXXX")
trap 'rm -rf -- "${stage}"' EXIT
mkdir "${stage}/bin"
cat > "${stage}/bin/docker" <<'EOF'
#!/usr/bin/env bash
touch "${LISKOV_RUNNER_TEST_SENTINEL}"
exit 99
EOF
cp "${stage}/bin/docker" "${stage}/bin/curl"
chmod 0755 "${stage}/bin/"*
export LISKOV_RUNNER_TEST_SENTINEL="${stage}/external-call"
export PATH="${stage}/bin:${PATH}"

refuses() {
  local expected=$1
  shift
  local status=0
  "${repo_root}/scripts/test-actions-runner-qemu-proot.sh" "$@" > "${stage}/output" 2>&1 || status=$?
  [[ ${status} -ne 0 && ${status} -ne 99 ]] || {
    echo 'invalid input was accepted or reached external execution' >&2; exit 1;
  }
  grep -Fq "${expected}" "${stage}/output"
  [[ ! -e ${LISKOV_RUNNER_TEST_SENTINEL} ]]
}

printf 'corrupted runner archive\n' > "${stage}/corrupt.tar.gz"
# Read the production pin so this regression cannot silently drift from it.
pin=$(sed -n 's/^runner_sha256=//p' "${repo_root}/scripts/test-actions-runner-qemu-proot.sh")
[[ ${pin} =~ ^[0-9a-f]{64}$ ]]
actual=$(sha256sum "${stage}/corrupt.tar.gz")
[[ ${actual%% *} != "${pin}" ]]
refuses 'runner archive digest mismatch' --runner-archive "${stage}/corrupt.tar.gz"
printf 'test credential; never printed\n' > "${stage}/jit"
chmod 0644 "${stage}/jit"
refuses 'mode-0600 file' --jitconfig-file "${stage}/jit"
chmod 0600 "${stage}/jit"
ln -s "${stage}/jit" "${stage}/jit-link"
refuses 'mode-0600 file' --jitconfig-file "${stage}/jit-link"
refuses 'offline evidence always tests both profiles' --profile netlink-denied
echo 'runner input refusals passed without download or guest startup'
