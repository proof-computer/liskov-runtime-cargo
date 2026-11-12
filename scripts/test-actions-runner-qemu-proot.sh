#!/usr/bin/env bash
# Local runner evidence only; real registration requires an operator's JIT file.
set -euo pipefail

runner_version=2.338.2
runner_sha256=670adb2f268fe21dcbb58b3db0e0aa9d5b3bddfe2c651481336e561ff86de945
runner_url="https://github.com/actions/runner/releases/download/v${runner_version}/actions-runner-linux-arm64-${runner_version}.tar.gz"
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
archive=
jit_file=
profile=processor-like
profile_given=0

usage() {
  cat <<'EOF'
usage: scripts/test-actions-runner-qemu-proot.sh [options]

Without credentials, verify the pinned runner's version and malformed-JIT
refusal under BOTH processor-like and netlink-denied profiles.

  --runner-archive FILE  Verify and use a local copy instead of the cache.
  --jitconfig-file FILE  Run one real JIT assignment; FILE must be mode 0600.
  --profile PROFILE      Live mode only: processor-like (default), netlink-denied.
  -h, --help             Show this help.

Live runner output stays private inside the disposable guest. Only readiness,
completion timing and status are printed. No credential is passed in argv.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --runner-archive | --jitconfig-file | --profile)
      [[ $# -ge 2 && -n $2 ]] || { echo "missing option value" >&2; exit 2; }
      case "$1" in
        --runner-archive) archive=$2 ;;
        --jitconfig-file) jit_file=$2 ;;
        --profile) profile=$2; profile_given=1 ;;
      esac
      shift 2
      ;;
    -h | --help) usage; exit 0 ;;
    *) echo "unknown option" >&2; usage >&2; exit 2 ;;
  esac
done
case "${profile}" in
  processor-like | netlink-denied) ;;
  *) echo "unsupported profile" >&2; exit 2 ;;
esac
if [[ ${profile_given} -eq 1 && -z ${jit_file} ]]; then
  echo "--profile requires --jitconfig-file; offline evidence always tests both profiles" >&2
  exit 2
fi
# Validate credentials before any download, Docker build, or guest execution.
if [[ -n ${jit_file} ]]; then
  if [[ ! -f ${jit_file} || -L ${jit_file} || ! -s ${jit_file} ]] ||
    [[ $(stat -c '%a' -- "${jit_file}") != 600 ]]; then
    echo "JIT configuration must be a nonempty regular, nonsymlink mode-0600 file" >&2
    exit 2
  fi
fi

verify_archive() {
  [[ -f $1 ]] && printf '%s  %s\n' "${runner_sha256}" "$1" |
    sha256sum --check --strict --status
}

umask 077
stage=$(mktemp -d "${TMPDIR:-/tmp}/liskov-actions-runner.XXXXXX")
partial=
cleanup() {
  [[ -z ${partial} ]] || rm -f -- "${partial}"
  rm -rf -- "${stage}"
}
trap cleanup EXIT
if [[ -z ${archive} ]]; then
  cache="${repo_root}/.cache/qemu-proot"
  mkdir -p "${cache}"
  archive="${cache}/${runner_sha256}.tar.gz"
  if [[ ! -e ${archive} ]]; then
    partial=$(mktemp "${cache}/runner-download.XXXXXX")
    curl --fail --location --silent --show-error --output "${partial}" "${runner_url}"
    verify_archive "${partial}" || { echo "runner archive digest mismatch" >&2; exit 1; }
    mv -- "${partial}" "${archive}"
    partial=
  fi
fi
verify_archive "${archive}" || { echo "runner archive digest mismatch or missing archive" >&2; exit 1; }
install -m 0600 -- "${archive}" "${stage}/runner.tar.gz"
install -m 0755 "${repo_root}/tools/qemu-proot/actions-runner-guest.sh" "${stage}/guest.sh"
mode=offline
profiles=(processor-like netlink-denied)
if [[ -n ${jit_file} ]]; then
  mode=live
  profiles=("${profile}")
  install -m 0600 -- "${jit_file}" "${stage}/jitconfig"
fi

for profile in "${profiles[@]}"; do
  echo "== Actions runner ${runner_version}: ${profile} (${mode})"
  "${repo_root}/scripts/run-qemu-proot-runtime.sh" \
    --profile "${profile}" --workspace "${stage}" -- \
    /bin/bash /workspace/guest.sh "${runner_version}" "${mode}" |
    tee "${stage}/${profile}.log"
  if [[ ${mode} == offline ]]; then
    sed -n 's/^liskov-runner-evidence: //p' "${stage}/${profile}.log" > "${stage}/${profile}.summary"
    [[ -s ${stage}/${profile}.summary ]] || { echo "guest evidence missing" >&2; exit 1; }
  fi
done
if [[ ${mode} == offline ]]; then
  diff -u "${stage}/processor-like.summary" "${stage}/netlink-denied.summary"
  echo "Actions runner evidence agrees under both profiles"
fi
