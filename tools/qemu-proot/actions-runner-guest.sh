#!/usr/bin/env bash
# Runs only inside the disposable guest; the host workspace is read-only.
set -euo pipefail
umask 077
[[ $# -eq 2 ]] || exit 2
expected_version=$1
mode=$2
case "${mode}" in offline | live) ;; *) exit 2 ;; esac
runner=$(mktemp -d /root/actions-runner.XXXXXX)
listener_pid=
cleanup() {
  if [[ -n ${listener_pid} ]]; then
    kill "${listener_pid}" 2>/dev/null || true
    wait "${listener_pid}" 2>/dev/null || true
  fi
  rm -rf -- "${runner}"
}
trap cleanup EXIT
cd "${runner}"
tar -xzf /workspace/runner.tar.gz
mkdir -p _diag _work

printf 'guest: uname=%s HOME=%s\n' "$(uname -m)" "${HOME}"
if [[ -f /etc/os-release ]]; then
  echo 'guest: /etc/os-release present'
  cat /etc/os-release
else
  echo 'guest: /etc/os-release missing'
fi
# ldd inspects the native apphosts and shared objects, including the .NET host.
command -v ldd >/dev/null
while IFS= read -r binary; do
  # ldd can return nonzero for non-dynamic objects; retain its dependency lines.
  ldd "${binary}" >> dependencies.txt 2>&1 || true
done < <(find bin -maxdepth 1 -type f \( -name '*.so' -o -perm /111 \) \
  ! -name '*.dll' ! -name '*.sh' | sort)
missing=$(sed -n 's/^[[:space:]]*\([^[:space:]]*\) => not found.*$/\1/p' dependencies.txt | sort -u | paste -sd,)
printf 'guest: missing shared libraries=%s\n' "${missing:-none}"
# This is a .NET host setting, not a runner-file patch or an image overlay.
invariant=0
if ! compgen -G '/usr/lib/aarch64-linux-gnu/libicuuc.so*' >/dev/null &&
   ! compgen -G '/lib/aarch64-linux-gnu/libicuuc.so*' >/dev/null; then
  export DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1
  invariant=1
fi
printf 'guest: DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=%s\n' "${invariant}"
set +e
timeout 120 bin/Runner.Listener --version > version.txt 2>&1
version_status=$?
set -e
if [[ ${version_status} -ne 0 ]] || ! grep -Fxq "${expected_version}" version.txt; then
  echo "Listener version failed: status=${version_status}" >&2
  cat version.txt >&2
  exit 1
fi
printf 'guest: version=%s status=%s\n' "${expected_version}" "${version_status}"

if [[ ${mode} == live ]]; then
  [[ -f /workspace/jitconfig && $(stat -c %a /workspace/jitconfig) == 600 ]] || exit 2
  # The runner consumes and removes this input variable. Never put it on argv.
  export ACTIONS_RUNNER_INPUT_JITCONFIG
  ACTIONS_RUNNER_INPUT_JITCONFIG=$(cat /workspace/jitconfig)
  start=${SECONDS}
  bin/Runner.Listener run > live.txt 2>&1 &
  listener_pid=$!
  unset ACTIONS_RUNNER_INPUT_JITCONFIG
  listening=
  completed=
  while :; do
    if [[ -z ${listening} ]] && grep -Fq 'Listening for Jobs' live.txt; then
      listening=$((SECONDS - start))
      printf 'live: start_to_listening_seconds=%s\n' "${listening}"
    fi
    if [[ -n ${listening} && -z ${completed} ]] && grep -Eq 'Job .* completed with result:' live.txt; then
      completed=$((SECONDS - start))
      printf 'live: start_to_job_completion_seconds=%s listening_to_job_completion_seconds=%s\n' \
        "${completed}" "$((completed - listening))"
    fi
    # Read the last output even if the Listener exited between polling ticks.
    kill -0 "${listener_pid}" 2>/dev/null || break
    sleep 1
  done
  set +e
  wait "${listener_pid}"
  status=$?
  set -e
  listener_pid=
  printf 'live: exit_status=%s elapsed_seconds=%s\n' "${status}" "$((SECONDS - start))"
  [[ ${status} -eq 0 && -n ${listening} && -n ${completed} ]]
  exit $?
fi

set +e
ACTIONS_RUNNER_INPUT_JITCONFIG='deliberately-not-base64!' \
  timeout 120 bin/Runner.Listener run > refusal.txt 2>&1
refusal_status=$?
set -e
if [[ ${refusal_status} -eq 0 || ${refusal_status} -ge 128 || ${refusal_status} -eq 124 ]] ||
   cmp -s version.txt refusal.txt ||
   grep -Eiq "error while loading shared libraries|Couldn't find a valid ICU package|Must not run interactively with sudo|Failed to (load|initialize|create).*([Cc]ore[Cc][Ll][Rr]|runtime)|hostfxr|hostpolicy|You must install.*(NET|framework)" refusal.txt ||
   ! grep -Eiq 'Base-64|base64|JIT.*(invalid|config)|FormatException' refusal.txt; then
  echo "malformed-JIT control failed: status=${refusal_status}" >&2
  cat refusal.txt >&2
  exit 1
fi
printf 'guest: malformed-JIT refusal status=%s\n' "${refusal_status}"
cat refusal.txt
printf 'runner-summary: version=%s version_status=%s refusal_status=%s missing=%s invariant=%s\n' \
  "${expected_version}" "${version_status}" "${refusal_status}" "${missing:-none}" "${invariant}"
