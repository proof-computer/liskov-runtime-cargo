#!/bin/sh
set -eu

if [ "$#" -ne 7 ]; then
  echo "usage: $0 <liskov-dropbear> <liskov-dropbearkey> <stock-loader> <stock-library-dir> <stock-ssh> <stock-ssh-keygen> <stock-nc>" >&2
  exit 2
fi

dropbear=$1
dropbearkey=$2
stock_loader=$3
stock_library_dir=$4
ssh_client=$5
ssh_keygen=$6
netcat=$7
for artifact in "${dropbear}" "${dropbearkey}" "${stock_loader}" "${ssh_client}" "${ssh_keygen}" "${netcat}"; do
  if [ ! -f "${artifact}" ] || [ ! -x "${artifact}" ]; then
    echo "managed access smoke: injected test artifact is unavailable" >&2
    exit 2
  fi
done
if [ ! -d "${stock_library_dir}" ]; then
  echo "managed access smoke: stock client library directory is unavailable" >&2
  exit 2
fi

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
dropbear_log=${private_root}/dropbear.log
openssh_log=${private_root}/openssh.log
pty_openssh_log=${private_root}/openssh-pty.log
qemu_aarch64=/tmp/liskov-qemu-aarch64-static
if [ ! -x "${qemu_aarch64}" ]; then
  echo "managed access smoke: explicit QEMU runner is unavailable" >&2
  exit 2
fi

"${dropbearkey}" -t ed25519 -f "${host_key}" >/dev/null
chmod 0600 "${host_key}"
"${stock_loader}" --library-path "${stock_library_dir}" \
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

# Dropbear re-executes accepted connections through /proc/self/fd for ASLR.
# QEMU user mode cannot redispatch that anonymous AArch64 executable, so make
# argv[0] intentionally unopenable and exercise Dropbear's straight-fork
# fallback. The release binary and production hardening flags remain exact.
"${qemu_aarch64}" -0 /tmp/liskov-dropbear-qemu-no-reexec "${dropbear}" -F -E -s -g -j -k \
  -p 127.0.0.1:2222 \
  -r "${host_key}" \
  -D "${authorization_dir}" \
  -P "${pid_file}" \
  >"${dropbear_log}" 2>&1 &
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
set +e
observed=$(
  "${stock_loader}" --library-path "${stock_library_dir}" "${ssh_client}" -vvv -T \
    -o BatchMode=yes \
    -o ClearAllForwardings=yes \
    -o HostKeyAlias=liskov-managed-canary \
    -o IdentitiesOnly=yes \
    -o "IdentityFile=${operator_key}" \
    -o "ProxyCommand=${stock_loader} --library-path ${stock_library_dir} ${netcat} 127.0.0.1 2222" \
    -o StrictHostKeyChecking=yes \
    -o "UserKnownHostsFile=${known_hosts}" \
    root@liskov-managed-canary \
    "test -r /etc/os-release && test -z \"\${LISKOV_RUNTIME_SSH_CREDENTIAL_V1-}\" && printf '%s' '${marker}'" \
    2>"${openssh_log}"
)
ssh_status=$?
set -e
if [ "${ssh_status}" -ne 0 ]; then
  echo "managed access smoke: stock OpenSSH failed with status ${ssh_status}" >&2
  sed -n '1,160p' "${openssh_log}" >&2
  sed -n '1,120p' "${dropbear_log}" >&2
  exit "${ssh_status}"
fi
test "${observed}" = "${marker}"

# The operator CLI opens an interactive PTY by default. Keep this separate from
# the non-interactive command above so the release gate proves both Dropbear
# session paths with the exact pinned server and stock OpenSSH client. Nested
# QEMU/PRoot cannot model TIOCSCTTY for the guest child, so assert the SSH PTY
# request itself here; the preceding command proves remote I/O and the processor
# gate owns terminal control and PTY I/O.
set +e
"${stock_loader}" --library-path "${stock_library_dir}" "${ssh_client}" -vvv -tt \
  -o BatchMode=yes \
  -o ClearAllForwardings=yes \
  -o HostKeyAlias=liskov-managed-canary \
  -o IdentitiesOnly=yes \
  -o "IdentityFile=${operator_key}" \
  -o "ProxyCommand=${stock_loader} --library-path ${stock_library_dir} ${netcat} 127.0.0.1 2222" \
  -o StrictHostKeyChecking=yes \
  -o "UserKnownHostsFile=${known_hosts}" \
  root@liskov-managed-canary \
  true \
  >/dev/null 2>"${pty_openssh_log}"
set -e
if ! grep -q 'PTY allocation request accepted on channel 0' "${pty_openssh_log}"; then
  echo "managed access smoke: stock OpenSSH did not confirm PTY acceptance" >&2
  sed -n '1,240p' "${pty_openssh_log}" >&2
  exit 1
fi
if grep -q 'PTY allocation request failed' "${pty_openssh_log}"; then
  echo "managed access smoke: stock OpenSSH reported a rejected PTY" >&2
  exit 1
fi

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

echo "managed access smoke passed: injected-static-toolchain low-port=denied loopback-2222=openssh pty=request-accepted customer-exit=23"
