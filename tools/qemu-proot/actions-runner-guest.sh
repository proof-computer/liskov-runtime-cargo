#!/usr/bin/env bash
set +x
set -euo pipefail
umask 077
version=${1:?pinned version required}
profile=${2:?profile required}
mode=${3:?mode required}
[[ ${mode} == offline || ${mode} == live ]] || exit 2
runner=$(mktemp -d /root/actions-runner.XXXXXX)
trap 'rm -rf -- "${runner}"' EXIT
tar -xzf /workspace/runner.tar.gz -C "${runner}"
cd "${runner}"
mkdir -p _diag _work

echo "== actions runner profile: ${profile}"
echo "uname=$(uname -m) HOME=${HOME}"
if [[ -f /etc/os-release ]]; then
  echo '/etc/os-release:'
  cat /etc/os-release
else
  echo '/etc/os-release: missing'
fi
command -v ldd >/dev/null || { echo 'needs: ldd unavailable; cannot inspect native closure'; exit 1; }
echo 'missing shared libraries (native ELF files in bin/ and externals/):'
find bin externals -type f \( -name '*.so' -o -name '*.so.*' -o -name '*.node' -o -perm /111 \) -print0 |
  while IFS= read -r -d '' binary; do
    [[ $(od -An -tx1 -N4 "${binary}") == ' 7f 45 4c 46' ]] || continue
    set +e
    dependencies=$(ldd "${binary}" 2>&1)
    dependency_status=$?
    set -e
    # Static ELF files need no closure. Any other ldd failure must be explained.
    if [[ ${dependency_status} -ne 0 ]] &&
       ! grep -Eq 'not found|not a dynamic executable|statically linked' <<< "${dependencies}"; then
      echo "cannot inspect native dependencies: ${binary}" >&2
      exit 1
    fi
    awk -v binary="${binary}" '/not found/ { print binary ": " $1 " => not found" }' <<< "${dependencies}"
  done | sort -u > missing-libraries.txt
if [[ -s missing-libraries.txt ]]; then cat missing-libraries.txt; else echo 'none'; fi
if compgen -G '/usr/lib/aarch64-linux-gnu/libicu*.so*' >/dev/null ||
   compgen -G '/lib/aarch64-linux-gnu/libicu*.so*' >/dev/null; then
  echo 'environment: ICU present; no globalization override'
else
  export DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1
  echo 'environment: DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1 (ICU absent)'
fi

set +e
timeout 120 bin/Runner.Listener --version > version.txt 2>&1
version_status=$?
set -e
echo "version status=${version_status} output:"
cat version.txt
[[ ${version_status} -eq 0 && $(cat version.txt) == "${version}" ]] || exit 1

if [[ ${mode} == offline ]]; then
  set +e
  ACTIONS_RUNNER_INPUT_JITCONFIG='deliberately-malformed-jit' \
    timeout 120 bin/Runner.Listener run > refusal.txt 2>&1
  refusal_status=$?
  set -e
  echo "malformed-JIT refusal status=${refusal_status} output:"
  cat refusal.txt
  [[ ${refusal_status} -gt 0 && ${refusal_status} -lt 124 ]] || exit 1
  ! cmp -s version.txt refusal.txt || exit 1
  ! grep -Eiq 'error while loading shared libraries|Couldn.t find a valid ICU package|Must not run interactively with sudo|failed to (load|initialize|create)|failed to resolve|hostfxr|hostpolicy|CoreCLR|libhost|fatal error|framework.*not found' refusal.txt || exit 1
  grep -Eiq 'jit|base.?64|FormatException' refusal.txt || exit 1
else
  # Assignment, not `env KEY=value ...`: the secret must never enter an argv.
  export ACTIONS_RUNNER_INPUT_JITCONFIG
  ACTIONS_RUNNER_INPUT_JITCONFIG=$(cat /workspace/jitconfig)
  start=$(date +%s)
  listening=0
  completed=0
  set +e
  bin/Runner.Listener run 2>&1 | while IFS= read -r line; do
    now=$(date +%s)
    case "${line}" in
      *'Listening for Jobs'*)
        echo "live profile=${profile} start-to-listening-seconds=$((now - start))"
        touch listening
        ;;
      *'Running job:'*) job_start=${now} ;;
      *'completed with result:'*)
        echo "live profile=${profile} start-to-job-completion-seconds=$((now - start))"
        if [[ -n ${job_start:-} ]]; then
          echo "live profile=${profile} job-runtime-seconds=$((now - job_start))"
        fi
        touch completed
        ;;
    esac
  done
  runner_status=${PIPESTATUS[0]}
  set -e
  unset ACTIONS_RUNNER_INPUT_JITCONFIG
  [[ ! -f listening ]] || listening=1
  [[ ! -f completed ]] || completed=1
  echo "live profile=${profile} exit-status=${runner_status} listening=${listening} completed=${completed}"
  [[ ${runner_status} -eq 0 && ${listening} -eq 1 && ${completed} -eq 1 ]]
fi
