#!/bin/sh
set -eu

socket_path=/tmp/liskov-local-tailscaled.sock
state_directory=/tmp/liskov-local-tailscale-state
daemon_log=/tmp/liskov-local-tailscaled.log
client_log=/tmp/liskov-local-tailscale-client.log
daemon_pid=

cleanup() {
  if [ -S "${socket_path}" ]; then
    /usr/bin/timeout 5s /workspace/tailscale --socket="${socket_path}" logout \
      >>"${client_log}" 2>&1 || true
  fi
  if [ -n "${daemon_pid}" ]; then
    kill -TERM "${daemon_pid}" 2>/dev/null || true
    wait "${daemon_pid}" 2>/dev/null || true
  fi
}
trap cleanup EXIT
trap 'exit 0' HUP INT TERM

mkdir -m 0700 "${state_directory}"
runtime_hostname=$(tr -d '\r\n' </workspace/hostname)
case "${runtime_hostname}" in
  liskov-prt-[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]) ;;
  *)
    echo local-provider-hostname-invalid
    exit 70
    ;;
esac

/workspace/tailscaled \
  --tun=userspace-networking \
  --state=mem: \
  --socket="${socket_path}" \
  --statedir="${state_directory}" \
  --port=0 \
  --no-logs-no-support \
  >"${daemon_log}" 2>&1 &
daemon_pid=$!

socket_ready=0
attempt=0
while [ "${attempt}" -lt 200 ]; do
  if [ -S "${socket_path}" ]; then
    socket_ready=1
    break
  fi
  if ! kill -0 "${daemon_pid}" 2>/dev/null; then
    break
  fi
  attempt=$((attempt + 1))
  sleep 0.1
done
if [ "${socket_ready}" -ne 1 ]; then
  echo local-provider-daemon-start-failed
  exit 70
fi

if ! /workspace/tailscale --socket="${socket_path}" up \
  --reset \
  --auth-key=file:/workspace/authkey \
  --hostname="${runtime_hostname}" \
  --ssh \
  --accept-dns=false \
  --accept-routes=false \
  --netfilter-mode=off \
  --report-posture=false \
  --timeout=60s \
  >"${client_log}" 2>&1; then
  echo local-provider-auth-failed
  exit 70
fi

echo local-provider-ready
while kill -0 "${daemon_pid}" 2>/dev/null; do
  sleep 1
done
echo local-provider-daemon-stopped
exit 70
