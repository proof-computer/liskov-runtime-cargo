#!/usr/bin/env bash
# Local evidence for BKLG-20261112-c4el; no registration in the default mode.
set +x
set -euo pipefail

runner_version=2.338.2
runner_sha256=670adb2f268fe21dcbb58b3db0e0aa9d5b3bddfe2c651481336e561ff86de945
runner_url="https://github.com/actions/runner/releases/download/v${runner_version}/actions-runner-linux-arm64-${runner_version}.tar.gz"
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
archive=
jitconfig_file=
profile=
check_inputs=0

usage() {
  cat <<'USAGE'
usage: scripts/test-actions-runner-qemu-proot.sh [options]

Without credentials, check the pinned runner's version and malformed-JIT refusal
under both processor-like and netlink-denied. Requires Docker and downloads the
digest-verified official runner once into .cache/qemu-proot/.

  --runner-archive FILE  Use an existing archive (the pinned digest still applies).
  --jitconfig-file FILE  Run one real JIT runner; FILE must be a regular 0600 file.
  --profile PROFILE     Live mode only; processor-like (default) or netlink-denied.
  --self-test-inputs     Prove digest and credential-mode refusals without Docker.
  -h, --help            Show help.

Live mode prints only lifecycle timings, never the configuration or runner logs.
It consumes a JIT configuration already minted by a person; it creates none.
USAGE
}

die() { echo "$*" >&2; exit 2; }
while [[ $# -gt 0 ]]; do
  case "$1" in
    --runner-archive | --jitconfig-file | --profile)
      [[ $# -ge 2 && -n $2 ]] || die "$1 requires a value"
      case "$1" in
        --runner-archive) archive=$2 ;;
        --jitconfig-file) jitconfig_file=$2 ;;
        --profile) profile=$2 ;;
      esac
      shift 2
      ;;
    -h | --help) usage; exit 0 ;;
    --self-test-inputs) check_inputs=1; shift ;;
    *) die "unknown option: $1" ;;
  esac
done
if [[ ${check_inputs} -eq 1 ]]; then
  # BKLG-20261112-c4el: regressions must refuse before even invoking Docker.
  test_stage=$(mktemp -d)
  trap 'rm -rf -- "${test_stage}"' EXIT
  mkdir "${test_stage}/bin"
  cat > "${test_stage}/bin/docker" <<'STUB'
#!/usr/bin/env bash
touch "${LISKOV_RUNNER_TEST_MARKER}"
exit 99
STUB
  chmod 0755 "${test_stage}/bin/docker"
  export LISKOV_RUNNER_TEST_MARKER="${test_stage}/guest-started"
  export PATH="${test_stage}/bin:${PATH}"
  printf 'corrupt archive\n' > "${test_stage}/corrupt.tar.gz"
  [[ $(sha256sum "${test_stage}/corrupt.tar.gz" | cut -d ' ' -f 1) != "${runner_sha256}" ]]
  if "$0" --runner-archive "${test_stage}/corrupt.tar.gz" > "${test_stage}/digest.log" 2>&1; then
    die 'corrupt archive was accepted'
  fi
  grep -q 'SHA-256 mismatch' "${test_stage}/digest.log"
  printf 'non-secret fixture\n' > "${test_stage}/jitconfig"
  chmod 0644 "${test_stage}/jitconfig"
  if "$0" --jitconfig-file "${test_stage}/jitconfig" > "${test_stage}/mode.log" 2>&1; then
    die 'non-0600 configuration was accepted'
  fi
  grep -q 'must have mode 0600' "${test_stage}/mode.log"
  [[ ! -e ${LISKOV_RUNNER_TEST_MARKER} ]] || die 'refusal started Docker'
  echo 'input refusals passed: corrupt digest, non-0600 JIT file; guest never started'
  exit 0
fi
case "${profile:-processor-like}" in
  processor-like | netlink-denied) ;;
  *) die "unsupported profile" ;;
esac
if [[ -n ${jitconfig_file} ]]; then
  [[ -f ${jitconfig_file} && ! -L ${jitconfig_file} && -s ${jitconfig_file} ]] ||
    die "JIT configuration must be a nonempty regular file"
  [[ $(stat -c '%a' -- "${jitconfig_file}") == 600 ]] ||
    die "JIT configuration must have mode 0600"
elif [[ -n ${profile} ]]; then
  die "--profile requires --jitconfig-file; offline proof always runs both profiles"
fi

umask 077
stage=$(mktemp -d "${TMPDIR:-/tmp}/liskov-actions-runner.XXXXXX")
partial=
cleanup() {
  [[ -z ${partial} ]] || rm -f -- "${partial}"
  rm -rf -- "${stage}"
}
trap cleanup EXIT
if [[ -n ${jitconfig_file} ]]; then
  install -m 0600 -- "${jitconfig_file}" "${stage}/jitconfig"
fi
if [[ -z ${archive} ]]; then
  cache="${repo_root}/.cache/qemu-proot"
  mkdir -p "${cache}"
  archive="${cache}/${runner_sha256}.tar.gz"
  if [[ ! -e ${archive} ]]; then
    partial=$(mktemp "${cache}/actions-runner.partial.XXXXXX")
    curl --fail --location --silent --show-error --output "${partial}" "${runner_url}"
    [[ $(sha256sum -- "${partial}" | cut -d ' ' -f 1) == "${runner_sha256}" ]] ||
      die "runner archive SHA-256 mismatch; guest not started"
    mv -- "${partial}" "${archive}"
    partial=
  fi
fi
[[ -f ${archive} ]] || die "runner archive is missing"
# Verify the staged bytes as well: extraction never races a mutable cache file.
install -m 0600 -- "${archive}" "${stage}/runner.tar.gz"
[[ $(sha256sum -- "${stage}/runner.tar.gz" | cut -d ' ' -f 1) == "${runner_sha256}" ]] ||
  die "runner archive SHA-256 mismatch; guest not started"
install -m 0755 "${repo_root}/tools/qemu-proot/actions-runner-guest.sh" "${stage}/guest.sh"

run_profile() {
  "${repo_root}/scripts/run-qemu-proot-runtime.sh" \
    --profile "$1" --workspace "${stage}" -- \
    /workspace/guest.sh "${runner_version}" "$1" "$2"
}
if [[ -n ${jitconfig_file} ]]; then
  run_profile "${profile:-processor-like}" live
else
  for profile in processor-like netlink-denied; do
    run_profile "${profile}" offline | sed -n '/^== actions runner profile:/,$p' |
      tee "${stage}/${profile}.summary"
    grep -qx "== actions runner profile: ${profile}" "${stage}/${profile}.summary"
  done
  # Everything except the label must agree, including dependencies and refusal.
  sed 's/processor-like/PROFILE/g' "${stage}/processor-like.summary" > "${stage}/first"
  sed 's/netlink-denied/PROFILE/g' "${stage}/netlink-denied.summary" > "${stage}/second"
  diff -u "${stage}/first" "${stage}/second"
  echo "actions runner proof passed under both profiles"
fi
