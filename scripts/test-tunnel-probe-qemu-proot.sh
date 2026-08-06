#!/usr/bin/env bash
# Offline self-test for liskov-tunnel-probe inside the maintained aarch64 rootfs.
#
# Runs the in-guest runner under both fault profiles so the environment probe is
# validated against known answers: `processor-like` keeps AF_NETLINK available,
# `netlink-denied` makes socket(AF_NETLINK, ...) return EPERM. A probe that
# cannot tell those two apart cannot be trusted to report a real processor's
# denials.
set -euo pipefail

usage() {
  cat <<'USAGE'
usage: scripts/test-tunnel-probe-qemu-proot.sh <aarch64-tunnel-probe>

Exercises the probe's discover classification, redaction, mutation guard,
loopback listener, and environment checks inside the exact runtime rootfs.
USAGE
}

if [[ ${1:-} == "--help" || ${1:-} == "-h" ]]; then
  usage
  exit 0
fi
if [[ $# -ne 1 ]]; then
  usage >&2
  exit 2
fi

probe=$1
if [[ ! -s ${probe} ]]; then
  echo "tunnel probe artifact is missing or empty: ${probe}" >&2
  exit 2
fi

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
runner="${repo_root}/tools/qemu-proot/tunnel-probe-runner.sh"
if [[ ! -s ${runner} ]]; then
  echo "in-guest runner is missing: ${runner}" >&2
  exit 2
fi

stage=$(mktemp -d "${TMPDIR:-/tmp}/liskov-tunnel-probe-selftest.XXXXXX")
trap 'rm -rf -- "${stage}"' EXIT
install -m 0755 "${probe}" "${stage}/liskov-tunnel-probe"
install -m 0755 "${runner}" "${stage}/tunnel-probe-runner.sh"

for profile in processor-like netlink-denied; do
  echo "== tunnel probe self-test under profile: ${profile}"
  "${repo_root}/scripts/run-qemu-proot-runtime.sh" \
    --profile "${profile}" \
    --workspace "${stage}" \
    -- /workspace/tunnel-probe-runner.sh /workspace/liskov-tunnel-probe
done

echo "tunnel probe self-test passed under both fault profiles"
