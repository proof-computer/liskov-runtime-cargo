#!/usr/bin/env bash
# Local, unregistered runner evidence for EPIC-20260822-u36q.
set -euo pipefail
umask 077

runner_version=2.338.2
runner_sha256=670adb2f268fe21dcbb58b3db0e0aa9d5b3bddfe2c651481336e561ff86de945
runner_url="https://github.com/actions/runner/releases/download/v${runner_version}/actions-runner-linux-arm64-${runner_version}.tar.gz"
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
archive=
jitconfig=
profile=
self_test=0

usage() {
  cat <<'USAGE'
usage: scripts/test-actions-runner-qemu-proot.sh [options]

By default, prove the pinned Listener version and malformed-JIT refusal under
both processor-like and netlink-denied, without registering with GitHub.
  --runner-archive FILE     Verify this archive instead of the digest cache.
  --jitconfig-file FILE     Run one real JIT runner; FILE must be mode 0600.
  --profile PROFILE        Live-mode profile (default processor-like).
  --self-test              Check digest and credential refusal without Docker.
  -h, --help               Show this help.

Live mode prints only milestone timings and status, never runner logs or the
JIT configuration. It requires a person-supplied, single-use JIT configuration.
USAGE
}
while [[ $# -gt 0 ]]; do
  case "$1" in
    --runner-archive | --jitconfig-file | --profile)
      [[ $# -ge 2 && -n $2 ]] || { usage >&2; exit 2; }
      case "$1" in
        --runner-archive) archive=$2 ;;
        --jitconfig-file) jitconfig=$2 ;;
        --profile) profile=$2 ;;
      esac
      shift 2 ;;
    -h | --help) usage; exit 0 ;;
    --self-test) self_test=1; shift ;;
    *) usage >&2; exit 2 ;;
  esac
done
if [[ ${self_test} -eq 1 ]]; then
  stage=$(mktemp -d "${TMPDIR:-/tmp}/liskov-runner-guards.XXXXXX")
  trap 'rm -rf -- "${stage}"' EXIT
  mkdir "${stage}/bin"
  cat > "${stage}/bin/docker" <<'STUB'
#!/bin/sh
touch "${LISKOV_RUNNER_TEST_MARKER}"
exit 99
STUB
  chmod 0700 "${stage}/bin/docker"
  export LISKOV_RUNNER_TEST_MARKER="${stage}/docker-started"
  export PATH="${stage}/bin:${PATH}"
  printf 'corrupted archive\n' > "${stage}/corrupt.tar.gz"
  actual=$(sha256sum "${stage}/corrupt.tar.gz")
  [[ ${actual%% *} != "${runner_sha256}" ]]
  if "$0" --runner-archive "${stage}/corrupt.tar.gz" > "${stage}/digest.log" 2>&1; then
    echo 'corrupted archive was accepted' >&2; exit 1
  fi
  grep -q 'FAILED' "${stage}/digest.log"
  printf 'not a credential\n' > "${stage}/jitconfig"
  chmod 0644 "${stage}/jitconfig"
  if "$0" --jitconfig-file "${stage}/jitconfig" > "${stage}/mode.log" 2>&1; then
    echo 'non-private credential file was accepted' >&2; exit 1
  fi
  grep -q 'mode-0600' "${stage}/mode.log"
  [[ ! -e ${LISKOV_RUNNER_TEST_MARKER} ]]
  echo 'runner guard self-test passed: corrupt digest and non-0600 JIT refused before Docker'
  exit 0
fi
if [[ -n ${jitconfig} ]]; then
  if [[ ! -f ${jitconfig} || -L ${jitconfig} || $(stat -c %a -- "${jitconfig}") != 600 ]]; then
    echo 'JIT configuration must be a regular, non-symlink mode-0600 file' >&2
    exit 2
  fi
elif [[ -n ${profile} ]]; then
  echo '--profile requires --jitconfig-file; offline proof always runs both profiles' >&2
  exit 2
fi
case "${profile:-processor-like}" in
  processor-like | netlink-denied) ;;
  *) echo 'unsupported profile' >&2; exit 2 ;;
esac

stage=$(mktemp -d "${TMPDIR:-/tmp}/liskov-actions-runner.XXXXXX")
trap 'rm -rf -- "${stage}"' EXIT
if [[ -z ${archive} ]]; then
  cache="${repo_root}/.cache/qemu-proot"
  mkdir -p "${cache}"
  archive="${cache}/${runner_sha256}.tar.gz"
  if [[ ! -e ${archive} ]]; then
    curl --fail --location --silent --show-error --output "${stage}/download" "${runner_url}"
    printf '%s  %s\n' "${runner_sha256}" "${stage}/download" | sha256sum --check --strict
    mv -- "${stage}/download" "${archive}"
  fi
fi
# Verify before Docker, extraction, or executing any guest command.
printf '%s  %s\n' "${runner_sha256}" "${archive}" | sha256sum --check --strict
install -m 0600 "${archive}" "${stage}/runner.tar.gz"
install -m 0700 "${repo_root}/tools/qemu-proot/actions-runner-guest.sh" "${stage}/guest.sh"
profiles=(processor-like netlink-denied)
mode=offline
if [[ -n ${jitconfig} ]]; then
  install -m 0600 "${jitconfig}" "${stage}/jitconfig"
  profiles=("${profile:-processor-like}")
  mode=live
fi
previous_summary=
for selected in "${profiles[@]}"; do
  echo "== actions runner under profile: ${selected}"
  "${repo_root}/scripts/run-qemu-proot-runtime.sh" \
    --profile "${selected}" --workspace "${stage}" -- \
    /bin/bash /workspace/guest.sh "${runner_version}" "${mode}" |
    tee "${stage}/${selected}.summary"
  if [[ ${mode} == offline ]]; then
    summary=$(sed -n '/^runner-summary: /p' "${stage}/${selected}.summary")
    [[ -n ${summary} && $(printf '%s\n' "${summary}" | wc -l) -eq 1 ]] || {
      echo 'guest did not produce exactly one summary' >&2; exit 1;
    }
    if [[ -n ${previous_summary} && ${summary} != "${previous_summary}" ]]; then
      echo 'runner summaries differ between profiles' >&2; exit 1
    fi
    previous_summary=${summary}
  fi
done
if [[ ${mode} == offline ]]; then
  echo 'actions runner offline proof passed under both fault profiles'
fi
