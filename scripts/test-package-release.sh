#!/usr/bin/env bash
set -euo pipefail

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
test_root=$(mktemp -d)
trap 'rm -rf "$test_root"' EXIT

cd "$repo_root"
printf '\177ELF deterministic fixture\n' >"${test_root}/helper"
printf '\177ELF deterministic dropbear fixture\n' >"${test_root}/dropbear"
printf '\177ELF deterministic dropbearkey fixture\n' >"${test_root}/dropbearkey"
chmod 0755 "${test_root}/helper"
chmod 0755 "${test_root}/dropbear" "${test_root}/dropbearkey"
source_commit=0123456789abcdef0123456789abcdef01234567

scripts/package-release.sh v0.10.0 "$source_commit" "${test_root}/helper" "${test_root}/dropbear" "${test_root}/dropbearkey" "${test_root}/one"
scripts/package-release.sh v0.10.0 "$source_commit" "${test_root}/helper" "${test_root}/dropbear" "${test_root}/dropbearkey" "${test_root}/two"

diff -ru "${test_root}/one" "${test_root}/two"
jq -e \
  --arg source_commit "$source_commit" \
  '
    .schema == "proof.liskov.runtime-contact-release" and
    .schemaVersion == 2 and
    .contractEpoch == 1 and
    .runtimeBootstrapDomain == "proof.liskov.runtime-bootstrap-request.v2" and
    .tag == "v0.10.0" and
    .version == "0.10.0" and
    .sourceCommit == $source_commit and
    .target == "aarch64-unknown-linux-musl" and
    .binary.asset == "liskov-runtime-contact-v0.10.0-aarch64-unknown-linux-musl" and
    .archive.asset == "liskov-runtime-contact-v0.10.0-aarch64-unknown-linux-musl.tar.gz" and
    .toolchain.dropbearVersion == "2026.94" and
    .toolchain.dropbear.asset == "liskov-dropbear-2026.94-v0.10.0-aarch64-unknown-linux-musl" and
    .toolchain.dropbearkey.asset == "liskov-dropbearkey-2026.94-v0.10.0-aarch64-unknown-linux-musl" and
    (.binary.sha256 | test("^[0-9a-f]{64}$")) and
    (.archive.sha256 | test("^[0-9a-f]{64}$")) and
    (.toolchain.dropbear.sha256 | test("^[0-9a-f]{64}$")) and
    (.toolchain.dropbearkey.sha256 | test("^[0-9a-f]{64}$")) and
    .binary.byteSize > 0 and
    .archive.byteSize > 0 and
    .toolchain.dropbear.byteSize > 0 and
    .toolchain.dropbearkey.byteSize > 0
  ' "${test_root}/one/runtime-contact-release.json" >/dev/null
(
  cd "${test_root}/one"
  sha256sum --check SHA256SUMS
)

if scripts/package-release.sh v0.10.0-rc.1 "$source_commit" "${test_root}/helper" "${test_root}/dropbear" "${test_root}/dropbearkey" "${test_root}/bad-tag"; then
  echo "prerelease tag unexpectedly accepted" >&2
  exit 1
fi
if scripts/package-release.sh v0.10.0 ABCD "${test_root}/helper" "${test_root}/dropbear" "${test_root}/dropbearkey" "${test_root}/bad-commit"; then
  echo "malformed source commit unexpectedly accepted" >&2
  exit 1
fi
