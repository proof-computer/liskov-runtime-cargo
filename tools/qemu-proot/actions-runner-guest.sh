#!/usr/bin/env bash
set -euo pipefail
ulimit -c 0
expected_version=${1:?expected version required}
profile=${2:?profile required}
mode=${3:?mode required}
[[ ${mode} == offline || ${mode} == live ]] || exit 2

runner_directory=$(mktemp -d /root/actions-runner.XXXXXX)
trap 'rm -rf -- "${runner_directory}"' EXIT
umask 077
tar -xzf /workspace/runner.tar.gz -C "${runner_directory}"
cd "${runner_directory}"
mkdir -p _diag _work
echo "profile=${profile}"
printf 'uname='; uname -m
printf 'HOME=%s\n' "${HOME}"
if [[ -f /etc/os-release ]]; then
  echo '/etc/os-release:'
  cat /etc/os-release
else
  echo '/etc/os-release: missing'
fi

# Include the bundled .NET host libraries and all native shared objects.
find bin externals -type f \( -name '*.so' -o -name '*.so.*' -o -name 'Runner.Listener' -o -name 'Runner.Worker' -o -path 'externals/*/bin/node' \) -print0 |
  while IFS= read -r -d '' binary; do
    ldd "${binary}" 2>&1 || true # Non-dynamic objects are also present in the archive.
  done >library-report
awk '/=> not found/ {print $1}' library-report | sort -u >missing-libraries
printf 'missing-shared-libraries='
if [[ -s missing-libraries ]]; then
  paste -sd, missing-libraries
else
  echo none
fi

# First attempt uses the rootfs environment as shipped. Only the documented ICU
# fallback is retried; other host failures remain evidence and fail this proof.
version_status=0
bin/Runner.Listener --version >version-output 2>&1 || version_status=$?
needs=none
if [[ ${version_status} -ne 0 ]] && grep -Fq "Couldn't find a valid ICU package" version-output; then
  echo 'unconfigured-startup: ICU package unavailable'
  export DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1
  needs=DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1
  version_status=0
  bin/Runner.Listener --version >version-output 2>&1 || version_status=$?
fi
echo "needs=${needs}"
cat version-output
[[ ${version_status} -eq 0 && $(tr -d '\r\n' <version-output) == "${expected_version}" ]] || {
  echo "runner version/startup check failed (status=${version_status})" >&2
  exit 1
}
echo "runner-version=${expected_version}"

if [[ ${mode} == offline ]]; then
  status=0
  ACTIONS_RUNNER_INPUT_JITCONFIG=deliberately-malformed-jit-config \
    bin/Runner.Listener run >refusal-output 2>&1 || status=$?
  echo "malformed-jit-status=${status}"
  cat refusal-output
  [[ ${status} -gt 0 && ${status} -lt 128 ]] && ! cmp -s version-output refusal-output || {
    echo "malformed JIT negative control did not bite" >&2; exit 1;
  }
  if grep -Eiq 'error while loading shared libraries|Couldn.t find a valid ICU package|Must not run interactively with sudo|Failed to (load|create).*CoreCLR|Failed to (locate|load).*host|You must install.*\.NET|libhostpolicy.*not found|A fatal error.*encountered' refusal-output; then
    echo "negative control failed before runner option parsing" >&2; exit 1
  fi
  grep -Eiq 'jit|base.?64|configuration' refusal-output || {
    echo "negative control did not report a JIT parsing refusal" >&2; exit 1;
  }
  printf 'malformed-jit-refusal=%s\n' "$(tr '\r\n' '  ' <refusal-output)"
else
  # Raw live output and _diag may contain credentials; keep them in disposable
  # guest storage and emit only fixed state markers and elapsed wall time.
  [[ -s /workspace/jitconfig && $(stat -c %a /workspace/jitconfig) == 600 ]] || exit 2
  jitconfig=$(cat /workspace/jitconfig)
  mkfifo live-output
  started=$(date +%s)
  (
    listening=0
    while IFS= read -r line; do
      now=$(date +%s)
      if [[ ${listening} -eq 0 && ${line} == *'Listening for Jobs'* ]]; then
        echo "listening-seconds=$((now - started))"
        listening=1
        touch listening-seen
      fi
      if [[ ${line} == *'completed with result:'* ]]; then
        echo "job-completion-seconds=$((now - started))"
        touch completion-seen
      fi
    done <live-output
  ) &
  reader=$!
  status=0
  ACTIONS_RUNNER_INPUT_JITCONFIG="${jitconfig}" bin/Runner.Listener run >live-output 2>&1 || status=$?
  unset jitconfig
  wait "${reader}"
  echo "live-runner-status=${status}"
  [[ ${status} -eq 0 && -f listening-seen && -f completion-seen ]] || {
    echo 'live runner failed or exited without listening and job completion' >&2
    exit 1
  }
fi
