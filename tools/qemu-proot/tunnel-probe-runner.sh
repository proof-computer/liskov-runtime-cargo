#!/bin/sh
# In-guest self-test for liskov-tunnel-probe.
#
# Runs inside the maintained Debian trixie aarch64 rootfs under QEMU/PRoot and
# checks the probe against known answers before it is ever pointed at a live
# processor. The rootfs has perl but no curl, so the loopback fetch is a perl
# one-liner.
set -eu

if [ $# -ne 1 ]; then
  echo "usage: tunnel-probe-runner.sh <probe-path>" >&2
  exit 2
fi

probe=$1
test -x "${probe}" || {
  echo "probe is not executable: ${probe}" >&2
  exit 2
}

work=/tmp/tunnel-probe-selftest
rm -rf "${work}"
mkdir -p "${work}"

fail() {
  echo "tunnel-probe-selftest: $1" >&2
  exit 1
}

# ---------------------------------------------------------------------------
# 1. discover against a scripted bridge
# ---------------------------------------------------------------------------
# The emulator sets BRIDGE_SOCKET to a deliberately unavailable name, so the
# self-test supplies its own server and overrides the variable per invocation.
cat > "${work}/replies.json" <<'JSON'
{
  "processor_version": {"result": {"platform": 0, "buildNumber": 130}},
  "tunnel_status": {"result": 1},
  "tunnel_certPem": {"result": "-----BEGIN CERTIFICATE-----\nQUJD\n-----END CERTIFICATE-----\n"},
  "tunnel_state": {"error": {"code": -32601, "message": "Method not found"}}
}
JSON

socket="liskov-tunnel-probe-selftest-$$"
"${probe}" fake-bridge \
  --socket "${socket}" \
  --replies-file "${work}/replies.json" \
  --max-requests 12 > "${work}/fake-bridge.ndjson" 2>&1 &
bridge_pid=$!
# shellcheck disable=SC2064
trap "kill ${bridge_pid} 2>/dev/null || true" EXIT
sleep 1

BRIDGE_SOCKET="${socket}" "${probe}" discover > "${work}/discover.ndjson" 2>&1 \
  || fail "discover exited non-zero"

grep -q '"method":"tunnel_status","nameVerdict":"supported"' "${work}/discover.ndjson" \
  || fail "discover did not classify tunnel_status as supported"
grep -q '"event":"tunnelStatus","ordinal":1,"state":"running"' "${work}/discover.ndjson" \
  || fail "discover did not decode the running status ordinal"
grep -q '"method":"tunnel_state","nameVerdict":"name_rejected"' "${work}/discover.ndjson" \
  || fail "discover did not classify an unknown name as rejected"
# The certificate body must never reach stdout.
grep -q '\[pem redacted' "${work}/discover.ndjson" \
  || fail "certificate reply was not redacted"
grep -q 'BEGIN CERTIFICATE' "${work}/discover.ndjson" \
  && fail "certificate body leaked into probe output"

# ---------------------------------------------------------------------------
# 2. mutation guard
# ---------------------------------------------------------------------------
echo '{}' > "${work}/empty-spec.json"
if BRIDGE_SOCKET="${socket}" "${probe}" start \
  --params-file "${work}/empty-spec.json" > "${work}/guard.ndjson" 2>&1; then
  fail "start without --yes-mutate should have failed"
fi
grep -q '"reason":"mutation_not_authorized"' "${work}/guard.ndjson" \
  || fail "start without --yes-mutate gave the wrong reason"

# ---------------------------------------------------------------------------
# 3. loopback listener reachable in-guest
# ---------------------------------------------------------------------------
"${probe}" serve \
  --listen 127.0.0.1:18081 \
  --body-tag selftest \
  --duration-secs 25 \
  --max-requests 4 > "${work}/serve.ndjson" 2>&1 &
serve_pid=$!
# shellcheck disable=SC2064
trap "kill ${bridge_pid} ${serve_pid} 2>/dev/null || true" EXIT
sleep 2

nonce="n$$"
perl -MIO::Socket::INET -e '
  my $s = IO::Socket::INET->new(PeerAddr => "127.0.0.1", PeerPort => 18081, Timeout => 10)
    or die "connect failed: $!";
  print $s "GET /probe/$ARGV[0] HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
  local $/; my $reply = <$s>; print $reply;
' "${nonce}" > "${work}/fetch.txt" || fail "loopback fetch failed"

grep -q "liskov-tunnel-probe selftest /probe/${nonce}" "${work}/fetch.txt" \
  || fail "loopback fetch did not return the tagged body"
sleep 1
grep -q "\"path\":\"/probe/${nonce}\"" "${work}/serve.ndjson" \
  || fail "listener did not log the request nonce"

# ---------------------------------------------------------------------------
# 4. environment probe reports a verdict for every check
# ---------------------------------------------------------------------------
# No outbound targets: the emulator's network is not the processor's, so only
# the local syscall verdicts are asserted here.
"${probe}" env-probe --tcp-target 127.0.0.1:18081 --udp-target 127.0.0.1:9 \
  > "${work}/env.ndjson" 2>&1 || fail "env-probe exited non-zero"

for check in netlink_socket so_mark so_bindtodevice read_proc_net_tcp udp_bind; do
  grep -q "\"check\":\"${check}\"" "${work}/env.ndjson" \
    || fail "env-probe omitted the ${check} verdict"
done

netlink_ok=$(grep '"check":"netlink_socket"' "${work}/env.ndjson" | grep -c '"ok":true' || true)
echo "tunnel-probe-selftest: netlink_socket ok=${netlink_ok}"
echo "tunnel-probe-selftest: all checks passed"
