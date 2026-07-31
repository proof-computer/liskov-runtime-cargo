#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: scripts/smoke-qemu-proot.sh <aarch64-helper>" >&2
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
