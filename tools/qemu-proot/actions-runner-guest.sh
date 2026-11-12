#!/usr/bin/env bash
set -euo pipefail
umask 077
expected_version=${1:?expected version required}
mode=${2:?offline or live required}
case "${mode}" in offline | live) ;; *) exit 2 ;; esac

# /workspace is read-only. Everything the unpatched runner writes stays here,
# and is removed with this guest through the emulator's own UID boundary.
mkdir -p /root/actions-runner
cd /root/actions-runner
tar -xzf /workspace/runner.tar.gz
mkdir -p _diag _work
evidence() { printf 'liskov-runner-evidence: %s\n' "$*"; }
evidence "uname=$(uname -m) HOME=${HOME}"
if [[ -f /etc/os-release ]]; then
  while IFS= read -r line; do evidence "os-release: ${line}"; done < /etc/os-release
else
  evidence 'missing: /etc/os-release'
fi

# ldd also checks the .NET native host and libraries not loaded by --version.
missing=0
for binary in bin/*; do
  [[ -f ${binary} ]] || continue
  [[ $(od -An -tx1 -N4 "${binary}") == ' 7f 45 4c 46' ]] || continue
  ldd_status=0
  ldd "${binary}" > dependency.log 2>&1 || ldd_status=$?
  if [[ ${ldd_status} -ne 0 ]] && ! grep -Fq 'not found' dependency.log; then
    cat dependency.log >&2
    echo "dependency inspection failed: ${binary}" >&2
    exit 1
  fi
  while IFS= read -r line; do
    missing=1
    evidence "missing-library ${binary}: ${line}"
  done < <(sed -n '/=> not found/s/^[[:space:]]*//p' dependency.log | sort -u)
done
[[ ${missing} -ne 0 ]] || evidence 'missing-libraries: none reported by ldd'
if ! compgen -G '/usr/lib/*/libicuuc.so*' >/dev/null &&
  ! compgen -G '/lib/*/libicuuc.so*' >/dev/null; then
  export DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1
  evidence 'needs: DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1 (ICU absent)'
fi
export RUNNER_ALLOW_RUNASROOT=1
evidence 'environment: RUNNER_ALLOW_RUNASROOT=1 (PRoot uid 0; wrappers only)'

version_status=0
bin/Runner.Listener --version > version.log 2>&1 || version_status=$?
cat version.log
if [[ ${version_status} -ne 0 ]] || ! grep -Fxq "${expected_version}" version.log; then
  echo "runner --version failed: status=${version_status}" >&2
  exit 1
fi
evidence "version=${expected_version} status=${version_status}"

if [[ ${mode} == offline ]]; then
  refusal_status=0
  ACTIONS_RUNNER_INPUT_JITCONFIG='deliberately-malformed-jit!' \
    timeout 120 bin/Runner.Listener run > refusal.log 2>&1 || refusal_status=$?
  cat refusal.log
  if [[ ${refusal_status} -eq 0 || ${refusal_status} -ge 124 ]] ||
    cmp -s version.log refusal.log ||
    grep -Eiq "error while loading shared libraries|Couldn't find a valid ICU package|Must not run interactively with sudo|Failed to (load|initialize|create)|fatal error|You must install or update .NET|libhostpolicy.*not found|hostfxr.*not found" refusal.log; then
    echo "negative control did not reach a normal runner refusal: status=${refusal_status}" >&2
    exit 1
  fi
  # Require the runner's configuration parser, not just any nonzero process.
  grep -Eiq 'base.?64|jit.*(invalid|malformed)|invalid.*jit|FormatException' refusal.log || {
    echo "negative control did not identify malformed JIT configuration" >&2
    exit 1
  }
  evidence "malformed-jit status=${refusal_status}"
  while IFS= read -r line; do evidence "refusal: ${line}"; done < refusal.log
  exit 0
fi

[[ -s /workspace/jitconfig && $(stat -c '%a' /workspace/jitconfig) == 600 ]] || exit 2
# Never expand this value into argv or print live runner logs. The env variable
# is the Listener's own input seam, consumed exactly like --jitconfig.
export ACTIONS_RUNNER_INPUT_JITCONFIG
ACTIONS_RUNNER_INPUT_JITCONFIG=$(cat /workspace/jitconfig)
start_ms=$(date +%s%3N)
bin/Runner.Listener run > live.log 2>&1 &
listener=$!
unset ACTIONS_RUNNER_INPUT_JITCONFIG
trap 'kill "${listener}" 2>/dev/null || true; wait "${listener}" 2>/dev/null || true' EXIT
ready=0
completed=0
observe_progress() {
  if [[ ${ready} -eq 0 ]] && grep -Fq 'Listening for Jobs' live.log; then
    echo "runner listening observed after $(( $(date +%s%3N) - start_ms )) ms"
    ready=1
  fi
  if [[ ${completed} -eq 0 ]] && grep -Eq 'Job .* completed with result:' live.log; then
    echo "job completion observed after $(( $(date +%s%3N) - start_ms )) ms"
    completed=1
  fi
}
while kill -0 "${listener}" 2>/dev/null; do
  observe_progress
  sleep 0.2
done
status=0
wait "${listener}" || status=$?
trap - EXIT
# Handle a short job finishing between two samples.
observe_progress
echo "runner exited after $(( $(date +%s%3N) - start_ms )) ms; status=${status}"
if [[ ${completed} -eq 0 ]]; then
  echo 'job completion was not observed' >&2
  exit 1
fi
[[ ${ready} -eq 1 && ${status} -eq 0 ]]
