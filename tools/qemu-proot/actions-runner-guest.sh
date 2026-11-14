#!/usr/bin/env bash
# Runs inside the disposable guest; no runner file is patched.
set -euo pipefail
set +x
umask 077
[[ $# -eq 2 ]] || exit 2
expected_version=$1
mode=$2
case "$mode" in offline | live) ;; *) exit 2 ;; esac

runner_directory=$(mktemp -d /root/actions-runner.XXXXXX)
trap 'rm -rf -- "$runner_directory"' EXIT
tar -xzf /workspace/runner.tar.gz -C "$runner_directory"
cd "$runner_directory"
mkdir -p _diag _work

echo "guest: uname=$(uname -m) HOME=$HOME"
if [[ -f /etc/os-release ]]; then
  echo 'guest: /etc/os-release present'
  cat /etc/os-release
else
  echo 'guest: /etc/os-release absent'
fi

# ldd covers the apphosts and every native .NET library, including optional ones.
ldd bin/Runner.Listener bin/Runner.Worker bin/Runner.PluginHost bin/*.so \
  externals/node*/bin/node > libraries.log 2>&1 || true
missing_libraries=$(sed -n 's/^[[:space:]]*\([^[:space:]]*\) => not found.*/\1/p' \
  libraries.log | sort -u | paste -sd, -)
[[ -n $missing_libraries ]] || missing_libraries=none
runtime_environment=none
if ! compgen -G '/usr/lib/*/libicuuc.so*' >/dev/null &&
  ! compgen -G '/lib/*/libicuuc.so*' >/dev/null; then
  export DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1
  runtime_environment=DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1
fi
echo "needs: missing-libraries=$missing_libraries environment=$runtime_environment"

set +e
timeout 180 bin/Runner.Listener --version > version.log 2>&1
version_status=$?
set -e
version=$(tr -d '\r' < version.log)
if [[ $version_status -ne 0 || $version != "$expected_version" ]]; then
  echo "runner --version failed (status=$version_status)" >&2
  # This command has never received credentials, so its diagnostics are public.
  cat version.log >&2
  exit 1
fi
echo "version: $version status=$version_status"

if [[ $mode == offline ]]; then
  set +e
  ACTIONS_RUNNER_INPUT_JITCONFIG='deliberately-not-base64!' \
    timeout 180 bin/Runner.Listener run > refusal.log 2>&1
  refusal_status=$?
  set -e
  cat refusal.log
  if [[ $refusal_status -eq 0 || $refusal_status -ge 128 || $refusal_status -eq 124 ]] ||
    cmp -s version.log refusal.log ||
    grep -Eiq "error while loading shared libraries|Couldn't find a valid ICU package|Must not run interactively with sudo|Failed to (create|load)|fatal error|hostfxr|hostpolicy|CoreCLR" refusal.log ||
    ! grep -q 'not a valid Base-64 string' refusal.log; then
    echo "malformed-JIT control did not prove runner option parsing (status=$refusal_status)" >&2
    exit 1
  fi
  echo "refusal: malformed-JIT Base-64 parsing status=$refusal_status"
else
  # Only the Listener inherits this third-party input. No shell wrapper or argv
  # contains it; the disposable rootfs also owns all runner diagnostic files.
  jitconfig=$(cat /workspace/jitconfig)
  [[ -n $jitconfig ]] || { echo 'empty JIT configuration' >&2; exit 2; }
  started=$(date +%s)
  set +e
  ACTIONS_RUNNER_INPUT_JITCONFIG="$jitconfig" bin/Runner.Listener run --once 2>&1 | (
    unset jitconfig
    listening=0
    completed=0
    while IFS= read -r line; do
      if [[ $listening -eq 0 && $line == *'Listening for Jobs'* ]]; then
        echo "live: listening-after-seconds=$(( $(date +%s) - started ))"
        listening=1
      fi
      if [[ $completed -eq 0 && $line == *'Job '*' completed with result:'* ]]; then
        echo "live: job-completed-after-seconds=$(( $(date +%s) - started ))"
        completed=1
      fi
    done
    [[ $listening -eq 1 && $completed -eq 1 ]]
  )
  statuses=("${PIPESTATUS[@]}")
  set -e
  unset jitconfig
  echo "live: listener-exit-status=${statuses[0]}"
  [[ ${statuses[0]} -eq 0 && ${statuses[1]} -eq 0 ]] || exit 1
fi
