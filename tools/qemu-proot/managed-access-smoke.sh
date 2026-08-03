#!/bin/sh
set -eu

if [ "$#" -ne 5 ]; then
  echo "usage: $0 <liskov-dropbear> <liskov-dropbearkey> <stock-ssh> <stock-ssh-keygen> <stock-nc>" >&2
  exit 2
fi

dropbear=$1
dropbearkey=$2
ssh_client=$3
ssh_keygen=$4
netcat=$5
for artifact in "${dropbear}" "${dropbearkey}" "${ssh_client}" "${ssh_keygen}" "${netcat}"; do
  if [ ! -f "${artifact}" ] || [ ! -x "${artifact}" ]; then
    echo "managed access smoke: injected test artifact is unavailable" >&2
    exit 2
  fi
done

private_root=/tmp/liskov-managed-access-smoke
dropbear_pid=

cleanup() {
  if [ -n "${dropbear_pid}" ]; then
    kill -TERM "${dropbear_pid}" 2>/dev/null || true
    wait "${dropbear_pid}" 2>/dev/null || true
  fi
  rm -rf -- "${private_root}"
}
trap cleanup EXIT HUP INT TERM

help=$("${dropbear}" -h 2>&1 || true)
for option in -D -F -E -s -g -j -k -p -r -P; do
  case "${help}" in
    *"${option}"*) ;;
    *)
      echo "managed access smoke: Dropbear option missing: ${option}" >&2
      exit 1
      ;;
  esac
done

mkdir -m 0700 "${private_root}"
authorization_dir=${private_root}/authorization
mkdir -m 0700 "${authorization_dir}"
host_key=${private_root}/dropbear-ed25519-host-key
operator_key=${private_root}/operator-ed25519
pid_file=${private_root}/dropbear.pid
known_hosts=${private_root}/known_hosts

"${dropbearkey}" -t ed25519 -f "${host_key}" >/dev/null
chmod 0600 "${host_key}"
"${ssh_keygen}" -q -t ed25519 -N '' -f "${operator_key}"
chmod 0600 "${operator_key}"
cp "${operator_key}.pub" "${authorization_dir}/authorized_keys"
chmod 0600 "${authorization_dir}/authorized_keys"

# The processor-shaped container fixes unprivileged_port_start at 1024.
"${dropbear}" -F -E -s -g -j -k \
  -p 127.0.0.1:22 \
  -r "${host_key}" \
  -D "${authorization_dir}" \
  -P "${pid_file}" \
  >/dev/null 2>&1 &
low_port_pid=$!
sleep 1
if kill -0 "${low_port_pid}" 2>/dev/null; then
  kill -TERM "${low_port_pid}" 2>/dev/null || true
  wait "${low_port_pid}" 2>/dev/null || true
  echo "managed access smoke: privileged port 22 unexpectedly succeeded" >&2
  exit 1
fi
wait "${low_port_pid}" 2>/dev/null || true

"${dropbear}" -F -E -s -g -j -k \
  -p 127.0.0.1:2222 \
  -r "${host_key}" \
  -D "${authorization_dir}" \
  -P "${pid_file}" \
  >/dev/null 2>&1 &
dropbear_pid=$!
sleep 1
kill -0 "${dropbear_pid}"

host_public_key=$("${dropbearkey}" -y -f "${host_key}" 2>/dev/null | sed -n 's/^\(ssh-ed25519 [^ ]*\).*$/\1/p')
case "${host_public_key}" in
  "ssh-ed25519 "*) ;;
  *)
    echo "managed access smoke: host public key unavailable" >&2
    exit 1
    ;;
esac
printf 'liskov-managed-canary %s\n' "${host_public_key}" >"${known_hosts}"
chmod 0600 "${known_hosts}"

marker=liskov-managed-qemu-proot-marker
observed=$(
  "${ssh_client}" -T \
    -o BatchMode=yes \
    -o ClearAllForwardings=yes \
    -o HostKeyAlias=liskov-managed-canary \
    -o IdentitiesOnly=yes \
    -o "IdentityFile=${operator_key}" \
    -o "ProxyCommand=${netcat} 127.0.0.1 2222" \
    -o StrictHostKeyChecking=yes \
    -o "UserKnownHostsFile=${known_hosts}" \
    root@liskov-managed-canary \
    "test -r /etc/os-release && test -z \"\${LISKOV_RUNTIME_SSH_CREDENTIAL_V1-}\" && printf '%s' '${marker}'"
)
test "${observed}" = "${marker}"

# Access-sidecar failure is independent of the customer's exact exit result.
/bin/sh -c 'sleep 1; exit 23' &
customer_pid=$!
kill -TERM "${dropbear_pid}"
wait "${dropbear_pid}" 2>/dev/null || true
dropbear_pid=
set +e
wait "${customer_pid}"
customer_status=$?
set -e
test "${customer_status}" -eq 23

echo "managed access smoke passed: injected-static-toolchain low-port=denied loopback-2222=openssh customer-exit=23"
