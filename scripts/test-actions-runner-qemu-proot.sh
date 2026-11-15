#!/usr/bin/env bash
# Local, on-demand evidence for BKLG-20261112-c4el / EPIC-20260822-u36q.
set -euo pipefail
umask 077

runner_version=2.338.2
runner_sha256=670adb2f268fe21dcbb58b3db0e0aa9d5b3bddfe2c651481336e561ff86de945
runner_url="https://github.com/actions/runner/releases/download/v${runner_version}/actions-runner-linux-arm64-${runner_version}.tar.gz"
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
archive=
jitconfig=
profile=

usage() {
  cat <<'EOF'
usage: scripts/test-actions-runner-qemu-proot.sh [options]

With no credentials, verify the pinned official ARM64 runner, inspect its
rootfs requirements, and assert version + malformed-JIT refusal in both profiles.

  --runner-archive FILE  Verify a local archive against the same pin (no download).
  --jitconfig-file FILE  Run one live JIT runner; FILE must be regular, mode 0600.
  --profile PROFILE     Live profile: processor-like (default) or netlink-denied.
  -h, --help            Show this help.

Live mode prints only readiness/completion timings and exit status, never runner
logs or JIT contents. It stops after one hour. Credentials are copied privately
into a disposable read-only workspace and passed to Listener in its environment.
Live registration and job execution require separate operator authorization.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --runner-archive | --jitconfig-file | --profile)
      [[ $# -ge 2 && -n $2 ]] || { echo "$1 requires a value" >&2; exit 2; }
      case "$1" in
        --runner-archive) archive=$2 ;;
        --jitconfig-file) jitconfig=$2 ;;
        --profile) profile=$2 ;;
      esac
      shift 2
      ;;
    -h | --help) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
done

if [[ -n ${profile} && ${profile} != processor-like && ${profile} != netlink-denied ]]; then
  echo "unsupported profile" >&2
  exit 2
fi
if [[ -z ${jitconfig} && -n ${profile} ]]; then
  echo "--profile is for live mode; offline proof always runs both profiles" >&2
  exit 2
fi
if [[ -n ${jitconfig} ]]; then
  if [[ ! -f ${jitconfig} || -L ${jitconfig} || ! -s ${jitconfig} ]] ||
    [[ $(stat -c %a -- "${jitconfig}") != 600 ]]; then
    echo "JIT configuration must be a nonempty regular file of mode 0600" >&2
    exit 2
  fi
fi

stage=$(mktemp -d "${TMPDIR:-/tmp}/liskov-actions-runner.XXXXXX")
trap 'rm -rf -- "${stage}"' EXIT
verify_archive() {
  [[ -f $1 ]] && printf '%s  %s\n' "${runner_sha256}" "$1" |
    sha256sum --check --strict --status
}
if [[ -z ${archive} ]]; then
  cache="${repo_root}/.cache/qemu-proot"
  mkdir -p "${cache}"
  archive="${cache}/${runner_sha256}.tar.gz"
  if [[ ! -e ${archive} ]]; then
    curl --fail --location --silent --show-error \
      --output "${stage}/download.tar.gz" "${runner_url}"
    verify_archive "${stage}/download.tar.gz" || {
      echo "runner archive SHA-256 mismatch; guest was not started" >&2; exit 1;
    }
    mv -- "${stage}/download.tar.gz" "${archive}"
  fi
fi
# Verify the exact staged bytes, including on cache hits, before any guest runs.
install -m 0600 "${archive}" "${stage}/runner.tar.gz"
verify_archive "${stage}/runner.tar.gz" || {
  echo "runner archive SHA-256 mismatch; guest was not started" >&2; exit 1;
}
install -m 0755 "${repo_root}/tools/qemu-proot/actions-runner-guest.sh" "${stage}/guest.sh"
mode=offline
profiles=(processor-like netlink-denied)
if [[ -n ${jitconfig} ]]; then
  install -m 0600 "${jitconfig}" "${stage}/jitconfig"
  mode=live
  profiles=("${profile:-processor-like}")
fi
for selected in "${profiles[@]}"; do
  echo "== Actions runner profile: ${selected} (${mode})"
  "${repo_root}/scripts/run-qemu-proot-runtime.sh" \
    --profile "${selected}" --workspace "${stage}" -- \
    /workspace/guest.sh "${mode}" "${runner_version}" |
    tee "${stage}/${selected}.out"
done
if [[ ${mode} == offline ]]; then
  for selected in "${profiles[@]}"; do
    sed -n '/^runner-summary:/p' "${stage}/${selected}.out" > "${stage}/${selected}.summary"
    [[ -s ${stage}/${selected}.summary ]] || { echo "missing guest summary" >&2; exit 1; }
  done
  cmp "${stage}/processor-like.summary" "${stage}/netlink-denied.summary"
  echo "Actions runner offline proof passed; both profile summaries agree"
fi
