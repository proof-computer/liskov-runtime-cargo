#!/usr/bin/env bash
# Build from one clean checkout and compare the shared transcript on host and ARM64.
set -euo pipefail

if [[ $# -ne 0 ]]; then
    echo "usage: scripts/test-traversal-scenario.sh" >&2
    exit 2
fi

cd "$(dirname "${BASH_SOURCE[0]}")/.."
repo=$(pwd -P)
source_sha=$(git rev-parse HEAD)
if [[ -n $(git status --porcelain --untracked-files=all) ]]; then
    echo "traversal evidence requires a clean checkout" >&2
    exit 2
fi

build_dir=$(cargo metadata --locked --no-deps --format-version 1 |
    python3 -c 'import json, sys; print(json.load(sys.stdin)["target_directory"])')
target=aarch64-unknown-linux-musl
cargo build --locked --bin liskov-runtime-contact
cargo build --locked --features fact-probe --bin liskov-fact-probe
cargo build --release --locked --target "$target" --bin liskov-runtime-contact
cargo build --release --locked --target "$target" --features fact-probe --bin liskov-fact-probe

host="$build_dir/debug"
arm64="$build_dir/$target/release"
for binary in liskov-runtime-contact liskov-fact-probe; do
    header=$(readelf -h "$arm64/$binary")
    segments=$(readelf -l "$arm64/$binary")
    if ! grep -q 'Machine:.*AArch64' <<<"$header" || grep -q 'Requesting program interpreter' <<<"$segments"; then
        echo "$binary is not a static AArch64 candidate" >&2
        exit 1
    fi
done

fixtures="$repo/tools/qemu-proot"
mkdir -p "$repo/target"
stage=$(mktemp -d "$repo/target/traversal-scenario.XXXXXX")
container="liskov-traversal-${stage##*.}"
cleanup() {
    docker rm -f "$container" >/dev/null 2>&1 || true
    rm -rf -- "$stage"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

mkdir "$stage/host" "$stage/guest"
install -m 0755 "$host/liskov-runtime-contact" "$host/liskov-fact-probe" "$stage/host/"
install -m 0755 "$arm64/liskov-runtime-contact" "$arm64/liskov-fact-probe" "$stage/guest/"
install -m 0644 "$fixtures/traversal-scenario-v1.json" "$fixtures/traversal-scenario-runner.sh" "$stage/guest/"
timeout --kill-after=5s 40s env -i PATH=/usr/bin:/bin /bin/sh "$stage/guest/traversal-scenario-runner.sh" \
    "$stage/host/liskov-fact-probe" "$stage/host/liskov-runtime-contact" \
    "$stage/guest/traversal-scenario-v1.json" >"$stage/host.json"
cmp "$fixtures/traversal-transcript-v1.json" "$stage/host.json"

for profile in processor-like netlink-denied; do
    timeout --kill-after=5s 180s scripts/run-qemu-proot-runtime.sh \
        --profile "$profile" --workspace "$stage/guest" --container-name "$container" -- \
        /bin/sh /workspace/traversal-scenario-runner.sh /workspace/liskov-fact-probe \
        /workspace/liskov-runtime-contact /workspace/traversal-scenario-v1.json >"$stage/$profile.json"
    cmp "$stage/host.json" "$stage/$profile.json"
done

if [[ $(git rev-parse HEAD) != "$source_sha" || -n $(git status --porcelain --untracked-files=all) ]]; then
    echo "source changed during traversal evidence capture" >&2
    exit 1
fi

python3 - "$source_sha" "$stage" "$target" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

source_sha, stage, target = sys.argv[1:]
stage = Path(stage)
request = stage / "guest" / "traversal-scenario-v1.json"

def sha256(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()

def binaries(directory):
    return {
        name: sha256(directory / name)
        for name in ("liskov-fact-probe", "liskov-runtime-contact")
    }

manifest = {
    "version": 1,
    "sourceSha": source_sha,
    "protocol": json.loads(request.read_text(encoding="utf-8")),
    "entrypoint": ["liskov-fact-probe", "--traversal-scenario"],
    "inputSha256": sha256(request),
    "transcriptSha256": sha256(stage / "host.json"),
    "host": {"binaries": binaries(stage / "host")},
    "guest": {
        "target": target,
        "profiles": ["processor-like", "netlink-denied"],
        "binaries": binaries(stage / "guest"),
    },
}
with (stage / "candidate-manifest.json").open("w", encoding="utf-8") as output:
    json.dump(manifest, output, indent=2)
    output.write("\n")
PY

evidence="$repo/target/traversal-evidence/$source_sha"
mkdir -p "$evidence"
install -m 0644 "$stage/host.json" "$evidence/transcript.json"
mv -- "$stage/candidate-manifest.json" "$evidence/candidate-manifest.json"
printf 'Traversal evidence at %s\n' "$evidence"
