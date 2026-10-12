#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo "usage: scripts/smoke-qemu-proot.sh <aarch64-helper> [aarch64-lib-test-executable]" >&2
  exit 2
fi

helper=$1
rootfs_url=https://github.com/proof-computer/liskov-runtime-images/releases/download/v0.1.0-rc.12/liskov-runtime-image-debian-trixie-aarch64.tar.xz
rootfs_sha256=0639e88db6b46cef6091acafe35dfb1b59c5e354463d969f1a9509451d118377

for tool in curl proot qemu-aarch64-static sha256sum tar; do
  command -v "${tool}" >/dev/null || {
    echo "required QEMU/PRoot smoke tool is missing: ${tool}" >&2
    exit 2
  }
done
test -s "${helper}"

smoke_root=$(mktemp -d "${TMPDIR:-/tmp}/liskov-runtime-cargo-smoke.XXXXXX")
trap 'rm -rf -- "${smoke_root}"' EXIT
archive="${smoke_root}/rootfs.tar.xz"

curl --fail --location --show-error --silent \
  --output "${archive}" \
  "${rootfs_url}"
printf '%s  %s\n' "${rootfs_sha256}" "${archive}" | sha256sum --check --strict
tar -xJf "${archive}" -C "${smoke_root}"
rootfs="${smoke_root}/liskov-debian-trixie-aarch64"
install -m 0755 "${helper}" "${rootfs}/tmp/liskov-runtime-contact"

proot -q "$(command -v qemu-aarch64-static)" -0 \
  -r "${rootfs}" \
  -b /dev \
  -b /proc \
  -b /sys \
  -w / \
  /tmp/liskov-runtime-contact --version

customer_marker="${rootfs}/tmp/customer-ran"
set +e
BRIDGE_SOCKET=liskov-runtime-cargo-qemu-proot-smoke \
  proot -q "$(command -v qemu-aarch64-static)" -0 \
    -r "${rootfs}" \
    -b /dev \
    -b /proc \
    -b /sys \
    -w / \
    /tmp/liskov-runtime-contact -- /bin/sh -c 'touch /tmp/customer-ran'
status=$?
set -e

if [[ ${status} -ne 70 ]]; then
  echo "expected fail-closed contact status 70, got ${status}" >&2
  exit 1
fi
if [[ -e "${customer_marker}" ]]; then
  echo "customer command ran before signed contact" >&2
  exit 1
fi

# Separate source/ABI handoff proof: the existing library test binary uses
# offline Bridge/HTTP seams, never a production bootstrap bypass. The release
# binary above still proves its version and fail-closed first-contact boundary.
if [[ $# -eq 2 ]]; then
  fixture=$(realpath "$2")
  repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
  for profile in processor-like netlink-denied; do
    "${repository_root}/scripts/run-qemu-proot-runtime.sh" \
      --profile "$profile" --workspace "$(dirname "$fixture")" -- \
      /usr/bin/env TMPDIR=/data/user/0/liskov-11fh-processor/cache \
      LISKOV_GUEST_DIRECT_FIXTURE=1 "/workspace/$(basename "$fixture")" \
      --exact supervisor::tests::guest_direct_handoff::guest_private_startup_handoff_and_signed_advertisement --nocapture --test-threads=1
    "${repository_root}/scripts/run-qemu-proot-runtime.sh" \
      --profile "$profile" --workspace "$(dirname "$fixture")" -- \
      "/workspace/$(basename "$fixture")" discovery::direct --nocapture --test-threads=1
  done
fi
