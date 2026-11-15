#!/usr/bin/env bash
set -euo pipefail

runner_version=2.338.2
runner_sha256=670adb2f268fe21dcbb58b3db0e0aa9d5b3bddfe2c651481336e561ff86de945
runner_url="https://github.com/actions/runner/releases/download/v${runner_version}/actions-runner-linux-arm64-${runner_version}.tar.gz"
repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
runner_archive=
jitconfig_file=
profile=processor-like
profile_selected=0

usage() {
  cat <<'EOF'
usage: scripts/test-actions-runner-qemu-proot.sh [options]

Without credentials, verify the pinned ARM64 Actions runner and its malformed-JIT
refusal under both processor-like and netlink-denied QEMU/PRoot profiles.

  --runner-archive FILE  Verify and use an existing archive instead of the cache.
  --jitconfig-file FILE  Opt in to one live, single-job run; requires mode 0600.
  --profile PROFILE      Live profile: processor-like (default) or netlink-denied.
  -h, --help             Show this help.

Live output reports only state transitions, exit status and wall-clock seconds.
Never put the JIT configuration itself in arguments. Live mode needs a GitHub
credential minted separately; the ordinary proof does not register a runner.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --runner-archive | --jitconfig-file | --profile)
      [[ $# -ge 2 && -n "$2" ]] || { echo "$1 requires a value" >&2; exit 2; }
      case "$1" in
        --runner-archive) runner_archive=$(realpath -- "$2") ;;
        --jitconfig-file) jitconfig_file=$(realpath -- "$2") ;;
        --profile) profile=$2; profile_selected=1 ;;
      esac
      shift 2
      ;;
    -h | --help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done
case "${profile}" in
  processor-like | netlink-denied) ;;
  *) echo "unsupported profile" >&2; exit 2 ;;
esac
if [[ -n "${jitconfig_file}" ]]; then
  [[ -f "${jitconfig_file}" && -s "${jitconfig_file}" && $(stat -c %a -- "${jitconfig_file}") == 600 ]] || {
    echo "JIT configuration must be a nonempty mode-0600 regular file" >&2
    exit 2
  }
elif [[ ${profile_selected} -eq 1 ]]; then
  echo "--profile requires --jitconfig-file; offline proof always runs both profiles" >&2
  exit 2
fi

cache_directory="${repository_root}/.cache/qemu-proot"
mkdir -p "${cache_directory}"
stage=$(mktemp -d "${TMPDIR:-/tmp}/liskov-actions-runner.XXXXXX")
download_partial=
container_name=
cleanup() {
  [[ -z "${download_partial}" ]] || rm -f -- "${download_partial}"
  rm -rf -- "${stage}"
}
interrupt() {
  if [[ -n "${container_name}" ]]; then
    docker rm --force "${container_name}" >/dev/null || echo 'failed to remove interrupted emulator container' >&2
  fi
  exit "$1"
}
trap cleanup EXIT
trap 'interrupt 130' INT
trap 'interrupt 143' TERM
umask 077

verify_archive() {
  [[ -f "$1" ]] && printf '%s  %s\n' "${runner_sha256}" "$1" | sha256sum --check --strict >/dev/null || {
    echo "runner archive missing or SHA-256 mismatch; guest not started" >&2
    return 1
  }
}
if [[ -z "${runner_archive}" ]]; then
  runner_archive="${cache_directory}/${runner_sha256}.tar.gz"
  if [[ ! -e "${runner_archive}" ]]; then
    download_partial=$(mktemp "${cache_directory}/runner-download.XXXXXX")
    curl --fail --location --show-error --silent --output "${download_partial}" "${runner_url}"
    verify_archive "${download_partial}"
    mv -- "${download_partial}" "${runner_archive}"
    download_partial=
  fi
fi
verify_archive "${runner_archive}"
install -m 0600 "${runner_archive}" "${stage}/runner.tar.gz"
# Verify the exact staged bytes, including when the input was concurrently replaced.
verify_archive "${stage}/runner.tar.gz"
install -m 0755 "${repository_root}/tools/qemu-proot/actions-runner-guest.sh" "${stage}/actions-runner-guest.sh"

mode=offline
profiles=(processor-like netlink-denied)
if [[ -n "${jitconfig_file}" ]]; then
  mode=live
  profiles=("${profile}")
  install -m 0600 "${jitconfig_file}" "${stage}/jitconfig"
fi
for profile in "${profiles[@]}"; do
  echo "== Actions runner under profile: ${profile} (${mode})"
  container_name="liskov-actions-runner-$$-${RANDOM}"
  "${repository_root}/scripts/run-qemu-proot-runtime.sh" \
    --profile "${profile}" --workspace "${stage}" --container-name "${container_name}" -- \
    /bin/bash /workspace/actions-runner-guest.sh "${runner_version}" "${profile}" "${mode}" |
    tee "${stage}/${profile}.summary"
  container_name=
done
if [[ ${mode} == offline ]]; then
  # These facts must agree; timings and profile names intentionally differ.
  for profile in "${profiles[@]}"; do
    sed -n '/^runner-version=/p; /^needs=/p; /^missing-shared-libraries=/p; /^malformed-jit-status=/p; /^malformed-jit-refusal=/p' \
      "${stage}/${profile}.summary" >"${stage}/${profile}.facts"
    [[ $(wc -l <"${stage}/${profile}.facts") -eq 5 ]] || { echo "missing guest summary" >&2; exit 1; }
  done
  diff -u "${stage}/processor-like.facts" "${stage}/netlink-denied.facts"
  echo "Actions runner proof passed under both profiles"
fi
