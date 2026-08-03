#!/usr/bin/env bash
set -euo pipefail

rootfs_url=https://github.com/proof-computer/liskov-runtime-images/releases/download/v0.1.0-rc.12/liskov-runtime-image-debian-trixie-aarch64.tar.xz
rootfs_sha256=0639e88db6b46cef6091acafe35dfb1b59c5e354463d969f1a9509451d118377
rootfs_name=liskov-debian-trixie-aarch64
profile=processor-like
rootfs_archive=
self_test=0
use_shim=1
guest_command=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --profile)
      [[ $# -ge 2 ]] || exit 2
      profile=$2
      shift 2
      ;;
    --rootfs-archive)
      [[ $# -ge 2 ]] || exit 2
      rootfs_archive=$2
      shift 2
      ;;
    --self-test)
      self_test=1
      shift
      ;;
    --no-shim)
      use_shim=0
      shift
      ;;
    --)
      shift
      guest_command=("$@")
      break
      ;;
    *)
      echo "unknown emulator option: $1" >&2
      exit 2
      ;;
  esac
done

case "${profile}" in
  processor-like | netlink-denied) ;;
  *)
    echo "unsupported emulator profile: ${profile}" >&2
    exit 2
    ;;
esac

for tool in curl proot qemu-aarch64-static sha256sum tar; do
  command -v "${tool}" >/dev/null || {
    echo "emulator tool is missing: ${tool}" >&2
    exit 2
  }
done

emulator_root=$(mktemp -d /tmp/liskov-qemu-proot.XXXXXX)
download_partial=
cleanup() {
  if [[ -n "${download_partial:-}" && -f "${download_partial}" ]]; then
    rm -f -- "${download_partial}"
  fi
  if [[ -n "${emulator_root:-}" && -d "${emulator_root}" ]]; then
    rm -rf -- "${emulator_root}"
  fi
}
trap cleanup EXIT

if [[ -z "${rootfs_archive}" ]]; then
  rootfs_archive="/cache/${rootfs_sha256}.tar.xz"
  if [[ ! -e "${rootfs_archive}" ]]; then
    download_partial="${rootfs_archive}.partial.$$"
    curl --fail --location --show-error --silent \
      --output "${download_partial}" \
      "${rootfs_url}"
    printf '%s  %s\n' "${rootfs_sha256}" "${download_partial}" |
      sha256sum --check --strict
    mv "${download_partial}" "${rootfs_archive}"
    download_partial=
  fi
fi
[[ -f "${rootfs_archive}" ]] || {
  echo "rootfs archive is missing: ${rootfs_archive}" >&2
  exit 2
}
printf '%s  %s\n' "${rootfs_sha256}" "${rootfs_archive}" |
  sha256sum --check --strict

tar --exclude="${rootfs_name}/dev/*" -xJf "${rootfs_archive}" -C "${emulator_root}"
rootfs="${emulator_root}/${rootfs_name}"
[[ -d "${rootfs}" && -x "${rootfs}/bin/sh" ]] || {
  echo "rootfs archive did not contain ${rootfs_name}" >&2
  exit 2
}
mkdir -p "${rootfs}/root" "${rootfs}/workspace"

qemu_aarch64=$(command -v qemu-aarch64-static)
proot_args=(
  proot
  -q "${qemu_aarch64}"
  -0
  --kill-on-exit
  --link2symlink
  -r "${rootfs}"
  -b /dev
  -b /proc
  -b /sys
  -b /dev/pts
  -b /workspace
  -b "${qemu_aarch64}:/tmp/liskov-qemu-aarch64-static"
  -w /root
)
if [[ ${self_test} -eq 1 ]]; then
  proot_args+=(
    -b /usr/local/libexec/liskov-network-probe-aarch64:/tmp/liskov-network-probe
  )
fi

guest_environment=(
  /usr/bin/env
  -i
  HOME=/root
  PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
  LANG=C.UTF-8
  "TERM=${TERM:-dumb}"
  BRIDGE_SOCKET=liskov-local-bridge-unavailable
  NETWORK_INTERCEPT_SOCKET=liskov-local-network-intercept-unavailable
)
if [[ ${use_shim} -eq 1 ]]; then
  guest_environment+=(LD_PRELOAD=/usr/local/lib/libgetifaddrs_override.so)
fi

run_guest() {
  if [[ "${profile}" == netlink-denied ]]; then
    deny-af-netlink "${proot_args[@]}" "${guest_environment[@]}" "$@"
  else
    "${proot_args[@]}" "${guest_environment[@]}" "$@"
  fi
}

if [[ ${self_test} -eq 1 ]]; then
  netlink_expectation=netlink-open
  [[ "${profile}" == netlink-denied ]] && netlink_expectation=netlink-eperm
  shim_expectation=shim-on
  [[ ${use_shim} -eq 0 ]] && shim_expectation=shim-off
  run_guest /tmp/liskov-network-probe \
    "${netlink_expectation}" \
    "${shim_expectation}"
fi

if [[ ${#guest_command[@]} -eq 0 ]]; then
  [[ ${self_test} -eq 1 ]] && exit 0
  guest_command=(/bin/sh)
fi
run_guest "${guest_command[@]}"
