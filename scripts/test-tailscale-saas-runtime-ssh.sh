#!/usr/bin/env bash
set -euo pipefail

repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
credential_file=
tailscale_archive=
yes_provider=0
tailscale_version=1.98.10
tailscale_archive_sha256=d74a84e07cb1948d9f09a23ae161417c6127e562949773705c95d0762be2809d
node_binary=${LISKOV_TEST_NODE_BIN:-node}

usage() {
  cat <<'EOF'
usage: scripts/test-tailscale-saas-runtime-ssh.sh --yes-provider \
  --credential-file FILE [--tailscale-archive FILE]

Run an opt-in provider-real Runtime SSH gate with the official ARM64 Tailscale
client inside the local QEMU/PRoot emulator. The credential JSON must contain
kind, tailnet, tag, oauthClientId, and oauthClientSecret. Its parent directory
must be mode 0700 and the file mode 0600.

The test creates one 15-minute, one-off, ephemeral, preauthorized key bound to
the configured tag, verifies the local Tailscale client is already online in
the same tailnet, exercises `tailscale ssh root@...`, and deletes only the
exact temporary key and device. It never switches the local client login.

Options:
  --yes-provider            Required acknowledgement of provider mutation.
  --credential-file FILE    Customer-owned canary credential JSON.
  --tailscale-archive FILE  Reuse the exact pinned official ARM64 archive.
  -h, --help                Show this help.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --yes-provider)
      yes_provider=1
      shift
      ;;
    --credential-file)
      [[ $# -ge 2 ]] || {
        echo "--credential-file requires a value" >&2
        exit 2
      }
      credential_file=$(realpath "$2")
      shift 2
      ;;
    --tailscale-archive)
      [[ $# -ge 2 ]] || {
        echo "--tailscale-archive requires a value" >&2
        exit 2
      }
      tailscale_archive=$(realpath "$2")
      shift 2
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      echo "unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

[[ ${yes_provider} -eq 1 ]] || {
  echo "--yes-provider is required" >&2
  exit 2
}
[[ -n "${credential_file}" && -f "${credential_file}" ]] || {
  echo "--credential-file must name a file" >&2
  exit 2
}
if [[ -n "${tailscale_archive}" && ! -f "${tailscale_archive}" ]]; then
  echo "--tailscale-archive must name a file" >&2
  exit 2
fi
for tool in curl docker grep sha256sum tar; do
  command -v "${tool}" >/dev/null || {
    echo "required local tool is missing: ${tool}" >&2
    exit 2
  }
done
command -v "${node_binary}" >/dev/null || {
  echo "Node.js is required for the secret-safe provider controller" >&2
  exit 2
}
"${node_binary}" --version >/dev/null || {
  echo "the selected Node.js command is not runnable" >&2
  exit 2
}
command -v tailscale >/dev/null || {
  echo "the local Tailscale client is required" >&2
  exit 2
}

test_root=$(mktemp -d /tmp/liskov-tailscale-saas.XXXXXX)
chmod 0700 "${test_root}"
workspace="${test_root}/workspace"
mkdir -m 0700 "${workspace}"
container_name="liskov-ts-saas-$$"
emulator_pid=
provider_cleanup_done=0
cleanup_failed=0

controller=(
  "${node_binary}"
  "${repository_root}/tools/qemu-proot/tailscale-saas-controller.mjs"
)

cleanup() {
  original_status=$?
  trap - EXIT HUP INT TERM
  set +e
  if docker container inspect "${container_name}" >/dev/null 2>&1; then
    if ! docker stop --timeout 5 "${container_name}" >/dev/null 2>&1; then
      docker kill "${container_name}" >/dev/null 2>&1
    fi
  fi
  if [[ -n "${emulator_pid}" ]]; then
    wait "${emulator_pid}" >/dev/null 2>&1
  fi
  if docker container inspect "${container_name}" >/dev/null 2>&1; then
    if ! docker rm --force "${container_name}" >/dev/null 2>&1; then
      cleanup_failed=1
      echo "exact emulator-container cleanup failed" >&2
    fi
  fi
  if [[ ${provider_cleanup_done} -eq 0 && -f "${workspace}/control-state.json" ]]; then
    if ! "${controller[@]}" cleanup "${credential_file}" "${workspace}" \
      >/dev/null 2>&1; then
      cleanup_failed=1
      echo "exact provider cleanup failed; protected state retained at ${test_root}" >&2
    fi
  fi
  if [[ ${cleanup_failed} -eq 0 ]]; then
    case "${test_root}" in
      /tmp/liskov-tailscale-saas.*) rm -rf -- "${test_root}" ;;
    esac
  fi
  if [[ ${cleanup_failed} -ne 0 ]]; then
    exit 70
  fi
  exit "${original_status}"
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM

if [[ -z "${tailscale_archive}" ]]; then
  tailscale_archive="${test_root}/tailscale.tgz"
  curl --fail --location --show-error --silent \
    --output "${tailscale_archive}" \
    "https://pkgs.tailscale.com/stable/tailscale_${tailscale_version}_arm64.tgz"
fi
printf '%s  %s\n' "${tailscale_archive_sha256}" "${tailscale_archive}" |
  sha256sum --check --strict >/dev/null

tar -xzf "${tailscale_archive}" -C "${test_root}"
tailscale_directory="${test_root}/tailscale_${tailscale_version}_arm64"
[[ -x "${tailscale_directory}/tailscale" && -x "${tailscale_directory}/tailscaled" ]] || {
  echo "the pinned archive has an unexpected shape" >&2
  exit 2
}
cp "${tailscale_directory}/tailscale" "${workspace}/tailscale"
cp "${tailscale_directory}/tailscaled" "${workspace}/tailscaled"
cp "${repository_root}/tools/qemu-proot/tailscale-saas-runner.sh" \
  "${workspace}/runner.sh"
chmod 0755 "${workspace}/tailscale" "${workspace}/tailscaled"
chmod 0700 "${workspace}/runner.sh"

"${controller[@]}" prepare "${credential_file}" "${workspace}"

status_log="${test_root}/emulator-status.log"
: >"${status_log}"
chmod 0600 "${status_log}"
"${repository_root}/scripts/run-qemu-proot-runtime.sh" \
  --workspace "${workspace}" \
  --container-name "${container_name}" \
  -- /bin/sh /workspace/runner.sh \
  >"${status_log}" 2>&1 &
emulator_pid=$!

ready=0
for _ in $(seq 1 180); do
  if grep -Fxq local-provider-ready "${status_log}"; then
    ready=1
    break
  fi
  if ! kill -0 "${emulator_pid}" 2>/dev/null; then
    break
  fi
  sleep 0.5
done
[[ ${ready} -eq 1 ]] || {
  echo "local provider startup did not reach readiness" >&2
  exit 70
}

"${controller[@]}" consume "${credential_file}" "${workspace}"

discover_result="${test_root}/discover-result.json"
: >"${discover_result}"
chmod 0600 "${discover_result}"
discovered=0
for _ in $(seq 1 30); do
  if "${controller[@]}" discover "${credential_file}" "${workspace}" \
    >"${discover_result}"; then
    discovered=1
    break
  fi
  sleep 1
done
[[ ${discovered} -eq 1 ]] || {
  echo "the exact temporary provider device was not discovered" >&2
  exit 70
}
cat "${discover_result}"

"${controller[@]}" ssh "${credential_file}" "${workspace}"

docker stop --timeout 5 "${container_name}" >/dev/null
wait "${emulator_pid}" >/dev/null 2>&1 || true
emulator_pid=

"${controller[@]}" cleanup "${credential_file}" "${workspace}"
provider_cleanup_done=1
echo "local Tailscale SaaS Runtime SSH gate passed"
