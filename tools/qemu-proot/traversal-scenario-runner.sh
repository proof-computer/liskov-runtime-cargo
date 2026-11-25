#!/bin/sh
# Shared by the host and the AArch64 guest.
set -eu

probe=$1
helper=$2
scenario=$3

"$helper" --version >&2
if refusal=$("$helper" --traversal-scenario -- /bin/true <"$scenario" 2>&1); then
    echo "runtime contact accepted a fixture-only argument" >&2
    exit 1
else
    status=$?
fi
if [ "$status" -ne 2 ] || ! printf '%s\n' "$refusal" | grep -Fq "unexpected argument '--traversal-scenario'"; then
    echo "runtime contact did not reject the fixture argument at CLI parsing" >&2
    exit 1
fi

exec "$probe" --traversal-scenario <"$scenario"
