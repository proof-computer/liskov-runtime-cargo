#!/usr/bin/env bash
# Runs only inside the disposable maintained rootfs; never patches the runner.
set -euo pipefail
umask 077
mode=${1:?expected offline or live}
expected_version=${2:?expected pinned version}
[[ ${mode} == offline || ${mode} == live ]] || exit 2
ulimit -c 0
runner=$(mktemp -d /root/actions-runner.XXXXXX)
trap 'rm -rf -- "${runner}"' EXIT
tar -xzf /workspace/runner.tar.gz -C "${runner}"
cd "${runner}"
mkdir -p _diag _work

echo "needs: uname=$(uname -m) HOME=${HOME}"
if [[ -f /etc/os-release ]]; then
  echo 'needs: /etc/os-release present'
  cat /etc/os-release
else
  echo 'needs: /etc/os-release missing'
fi
# Include the managed app hosts, bundled .NET native libraries, and Node hosts.
# ldd's status also covers static/non-ELF inputs; retain only unresolved entries.
command -v ldd >/dev/null
for binary in bin/Runner.Listener bin/Runner.Worker bin/Runner.PluginHost bin/*.so externals/node*/bin/node; do
  [[ -f ${binary} ]] || continue
  ldd "${binary}" > library.out 2>&1 || true
  awk -v binary="${binary}" '/=> not found/ {print "needs: " binary ": " $1 " missing"}' library.out
  cat library.out >> libraries.out
done
awk '/=> not found/ {print $1}' libraries.out | sort -u > missing-libraries
missing=$(paste -sd, missing-libraries)
echo "needs: missing shared libraries=${missing:-none}"
set +e
timeout --signal=TERM --kill-after=10s 120s bin/Runner.Listener --version > version.out 2>&1
version_status=$?
set -e
if [[ ${version_status} != 0 ]] && grep -Fq "Couldn't find a valid ICU package" version.out; then
  echo "needs: default .NET startup status=${version_status}; ICU missing; DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1"
  export DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1
  set +e
  timeout --signal=TERM --kill-after=10s 120s bin/Runner.Listener --version > version.out 2>&1
  version_status=$?
  set -e
fi
invariant=${DOTNET_SYSTEM_GLOBALIZATION_INVARIANT:-unset}
version=$(tr -d '\r' < version.out)
echo "version: status=${version_status} output=${version}"
[[ ${version_status} == 0 && ${version} == "${expected_version}" ]] || exit 1

if [[ ${mode} == offline ]]; then
  # Deliberately invalid Base64: refusal must be in managed option parsing.
  export ACTIONS_RUNNER_INPUT_JITCONFIG='!liskov-malformed-jit!'
  set +e
  timeout --signal=TERM --kill-after=10s 120s bin/Runner.Listener run > refusal.out 2>&1
  refusal_status=$?
  set -e
  unset ACTIONS_RUNNER_INPUT_JITCONFIG
  echo "refusal: status=${refusal_status}"
  head -c 8192 refusal.out
  echo
  [[ ${refusal_status} -gt 0 && ${refusal_status} -lt 124 ]] || exit 1
  ! cmp -s version.out refusal.out || exit 1
  if grep -Eiq "error while loading shared libraries|Couldn't find a valid ICU package|Must not run interactively with sudo|Failed to (create|initialize)|Failed to load|You must install|A fatal error|hostfxr|hostpolicy|CoreCLR|segmentation fault|Unhandled exception" refusal.out; then
    echo 'negative control failed before managed JIT parsing' >&2
    exit 1
  fi
  grep -Eiq 'Base-64|Base64|base64' refusal.out || {
    echo 'negative control did not report malformed Base64' >&2; exit 1;
  }
  echo "runner-summary: version=${version} version_status=${version_status} refusal=malformed-base64 refusal_status=${refusal_status} missing=${missing:-none} invariant=${invariant}"
else
  # The secret is an environment value, never an argument to env or Listener.
  export ACTIONS_RUNNER_INPUT_JITCONFIG
  ACTIONS_RUNNER_INPUT_JITCONFIG=$(cat /workspace/jitconfig)
  start_ms=$(date +%s%3N)
  set +e
  timeout --signal=TERM --kill-after=10s 3600s bin/Runner.Listener run 2>&1 |
    (
      listening=0
      completed=0
      while IFS= read -r line; do
        if [[ ${listening} == 0 && ${line} == *'Listening for Jobs'* ]]; then
          echo "live: listening_after_ms=$(( $(date +%s%3N) - start_ms ))"
          listening=1
        fi
        if [[ ${completed} == 0 && ${line} == *' completed with result: '* ]]; then
          echo "live: job_completed_after_ms=$(( $(date +%s%3N) - start_ms ))"
          completed=1
        fi
      done
      [[ ${listening} == 1 && ${completed} == 1 ]]
    )
  statuses=("${PIPESTATUS[@]}")
  set -e
  unset ACTIONS_RUNNER_INPUT_JITCONFIG
  echo "live: runner_exit=${statuses[0]} timing_events_status=${statuses[1]}"
  [[ ${statuses[0]} == 0 && ${statuses[1]} == 0 ]]
fi
