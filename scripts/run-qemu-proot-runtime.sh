#!/usr/bin/env bash
set -euo pipefail

repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
tool_context="${repository_root}/tools/qemu-proot"
tool_image=liskov-runtime-cargo-qemu-proot:local
workspace=$(pwd -P)
rootfs_archive=
profile=processor-like
self_test=0
use_shim=1
guest_command=()

usage() {
  cat <<'EOF'
usage: scripts/run-qemu-proot-runtime.sh [options] [-- command [args...]]

Run an AArch64 command in the exact maintained Liskov Cargo rootfs through
QEMU and the APK-derived Acurast PRoot command shape.

Options:
  --profile processor-like  Keep AF_NETLINK available (default).
  --profile netlink-denied  Return EPERM from socket(AF_NETLINK, ...).
  --rootfs-archive FILE     Use and verify an existing exact rootfs archive.
  --workspace DIRECTORY     Bind this directory read-only at /workspace.
  --no-shim                 Do not preload the getifaddrs loopback shim.
  --self-test               Check PRoot, TCP, netlink profile, and the shim.
  -h, --help                Show this help.

With no command, an interactive /bin/sh is started. Paths passed to the guest
must be guest paths; files below the selected workspace appear at /workspace.
Do not place credentials in command arguments. Mount a mode-0600 file below
the workspace and let the candidate consume that file instead.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --profile)
      [[ $# -ge 2 ]] || {
        echo "--profile requires a value" >&2
        exit 2
      }
      profile=$2
      shift 2
      ;;
    --rootfs-archive)
      [[ $# -ge 2 ]] || {
        echo "--rootfs-archive requires a file" >&2
        exit 2
      }
      rootfs_archive=$(realpath "$2")
      shift 2
      ;;
    --workspace)
      [[ $# -ge 2 ]] || {
        echo "--workspace requires a directory" >&2
        exit 2
      }
      workspace=$(realpath "$2")
      shift 2
      ;;
    --no-shim)
      use_shim=0
      shift
      ;;
    --self-test)
      self_test=1
      shift
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    --)
      shift
      guest_command=("$@")
      break
      ;;
    *)
      echo "unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

case "${profile}" in
  processor-like | netlink-denied) ;;
  *)
    echo "unsupported profile: ${profile}" >&2
    exit 2
    ;;
esac

[[ -d "${workspace}" ]] || {
  echo "workspace is not a directory: ${workspace}" >&2
  exit 2
}
if [[ -n "${rootfs_archive}" && ! -f "${rootfs_archive}" ]]; then
  echo "rootfs archive is not a file: ${rootfs_archive}" >&2
  exit 2
fi
command -v docker >/dev/null || {
  echo "docker is required for the local QEMU/PRoot runtime" >&2
  exit 2
}

cache_directory="${repository_root}/.cache/qemu-proot"
mkdir -p "${cache_directory}"

docker build --quiet --tag "${tool_image}" "${tool_context}" >/dev/null

container_args=(
  run
  --rm
  --init
  --interactive
  --user "$(id -u):$(id -g)"
  --cap-drop ALL
  --cap-add SYS_PTRACE
  --security-opt no-new-privileges=true
  --security-opt label=disable
  --sysctl net.ipv4.ip_unprivileged_port_start=1024
  --mount "type=bind,src=${workspace},dst=/workspace,readonly"
  --mount "type=bind,src=${cache_directory},dst=/cache"
)
if [[ -t 0 && -t 1 ]]; then
  container_args+=(--tty)
fi

inner_args=(--profile "${profile}")
if [[ ${use_shim} -eq 0 ]]; then
  inner_args+=(--no-shim)
fi
if [[ ${self_test} -eq 1 ]]; then
  inner_args+=(--self-test)
fi
if [[ -n "${rootfs_archive}" ]]; then
  container_args+=(--mount "type=bind,src=${rootfs_archive},dst=/input-rootfs.tar.xz,readonly")
  inner_args+=(--rootfs-archive /input-rootfs.tar.xz)
fi
if [[ ${#guest_command[@]} -gt 0 ]]; then
  inner_args+=(-- "${guest_command[@]}")
fi

exec docker "${container_args[@]}" "${tool_image}" "${inner_args[@]}"
