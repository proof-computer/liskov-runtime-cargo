#!/usr/bin/env bash
# Local runner evidence for EPIC-20260822-u36q; never registers a runner by default.
set -euo pipefail
set +x

runner_version=2.338.2
runner_sha256=670adb2f268fe21dcbb58b3db0e0aa9d5b3bddfe2c651481336e561ff86de945
runner_url="https://github.com/actions/runner/releases/download/v${runner_version}/actions-runner-linux-arm64-${runner_version}.tar.gz"
repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
runner_archive=
jitconfig_file=
profile=processor-like
profile_selected=0

usage() {
  cat <<'USAGE'
usage: scripts/test-actions-runner-qemu-proot.sh [options]

Without credentials, prove the pinned unpatched runner's version and malformed
JIT refusal under both processor-like and netlink-denied profiles.

  --runner-archive FILE  Verify and use a local archive instead of the cache.
  --jitconfig-file FILE Run one live job using a mode-0600 JIT configuration.
  --profile PROFILE     Live mode only: processor-like (default) or netlink-denied.
  -h, --help            Show this help.

The live mode prints only timing/status markers, never raw runner output or
the JIT configuration. It requires an operator-supplied, single-use config.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --runner-archive | --jitconfig-file | --profile)
      [[ $# -ge 2 && -n $2 ]] || { echo "$1 requires a value" >&2; exit 2; }
      case "$1" in
        --runner-archive) runner_archive=$2 ;;
        --jitconfig-file) jitconfig_file=$2 ;;
        --profile) profile=$2; profile_selected=1 ;;
      esac
      shift 2
      ;;
    -h | --help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done
case "$profile" in
  processor-like | netlink-denied) ;;
  *) echo "unsupported profile: $profile" >&2; exit 2 ;;
esac
if [[ -n $jitconfig_file ]]; then
  if [[ ! -f $jitconfig_file || -L $jitconfig_file ]] ||
    [[ $(stat -c '%a' -- "$jitconfig_file") != 600 ]]; then
    echo "JIT configuration must be a regular, non-symlink mode-0600 file" >&2
    exit 2
  fi
elif [[ $profile_selected -eq 1 ]]; then
  echo "--profile is only used with --jitconfig-file; offline proof runs both" >&2
  exit 2
fi

stage=$(mktemp -d "${TMPDIR:-/tmp}/liskov-actions-runner.XXXXXX")
download_partial=
cleanup() {
  [[ -z $download_partial ]] || rm -f -- "$download_partial"
  rm -rf -- "$stage"
}
trap cleanup EXIT

verify_archive() {
  [[ -f $1 ]] || { echo "runner archive is missing" >&2; return 1; }
  if [[ $(sha256sum -- "$1" | cut -d ' ' -f 1) != "$runner_sha256" ]]; then
    echo "runner archive SHA-256 mismatch; refusing before guest startup" >&2
    return 1
  fi
}

if [[ -z $runner_archive ]]; then
  cache_directory="${repository_root}/.cache/qemu-proot"
  mkdir -p "$cache_directory"
  runner_archive="${cache_directory}/${runner_sha256}.tar.gz"
  if [[ ! -e $runner_archive ]]; then
    download_partial=$(mktemp "${runner_archive}.partial.XXXXXX")
    curl --fail --location --silent --show-error --retry 3 \
      --output "$download_partial" "$runner_url"
    verify_archive "$download_partial"
    mv -- "$download_partial" "$runner_archive"
    download_partial=
  fi
fi
verify_archive "$runner_archive"
install -m 0644 -- "$runner_archive" "$stage/runner.tar.gz"
install -m 0755 -- "${repository_root}/tools/qemu-proot/actions-runner-guest.sh" \
  "$stage/actions-runner-guest.sh"

profiles=(processor-like netlink-denied)
guest_mode=offline
if [[ -n $jitconfig_file ]]; then
  install -m 0600 -- "$jitconfig_file" "$stage/jitconfig"
  profiles=("$profile")
  guest_mode=live
fi
for profile in "${profiles[@]}"; do
  echo "== actions runner under profile: $profile"
  "${repository_root}/scripts/run-qemu-proot-runtime.sh" \
    --profile "$profile" --workspace "$stage" -- \
    /bin/bash /workspace/actions-runner-guest.sh "$runner_version" "$guest_mode" \
    | tee "$stage/$profile.summary"
done
if [[ $guest_mode == offline ]]; then
  # Compare the guest's observed needs and control results, excluding Docker noise.
  for profile in "${profiles[@]}"; do
    sed -n '/^needs:/p; /^version:/p; /^refusal:/p' \
      "$stage/$profile.summary" > "$stage/$profile.comparable"
    [[ $(wc -l < "$stage/$profile.comparable") -eq 3 ]] || {
      echo "guest summary is incomplete" >&2; exit 1;
    }
  done
  cmp "$stage/processor-like.comparable" "$stage/netlink-denied.comparable"
  echo "actions runner proof passed; both profiles agree"
fi
