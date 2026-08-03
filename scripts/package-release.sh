#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 6 ]; then
  echo "usage: $0 <tag> <source-commit> <binary-path> <dropbear-path> <dropbearkey-path> <output-dir>" >&2
  exit 2
fi

tag=$1
source_commit=$2
binary_path=$3
dropbear_path=$4
dropbearkey_path=$5
output_dir=$6
target=aarch64-unknown-linux-musl
dropbear_version=2026.94

if ! printf '%s\n' "$tag" | grep -Eq '^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'; then
  echo "release tag must be stable vMAJOR.MINOR.PATCH" >&2
  exit 2
fi
if ! printf '%s\n' "$source_commit" | grep -Eq '^[0-9a-f]{40}$'; then
  echo "source commit must be 40 lowercase hexadecimal characters" >&2
  exit 2
fi
if [ ! -s "$binary_path" ]; then
  echo "release binary is missing or empty" >&2
  exit 2
fi
if [ ! -s "$dropbear_path" ] || [ ! -s "$dropbearkey_path" ]; then
  echo "Dropbear toolchain binaries are missing or empty" >&2
  exit 2
fi

version=${tag#v}
asset="liskov-runtime-contact-${tag}-${target}"
archive="${asset}.tar.gz"
dropbear_asset="liskov-dropbear-${dropbear_version}-${tag}-${target}"
dropbearkey_asset="liskov-dropbearkey-${dropbear_version}-${tag}-${target}"
stage_dir="${output_dir}/.${asset}.stage"

mkdir -p "$output_dir"
rm -rf "$stage_dir"
mkdir -p "${stage_dir}/${asset}"
install -m 0755 "$binary_path" "${output_dir}/${asset}"
install -m 0755 "$binary_path" "${stage_dir}/${asset}/liskov-runtime-contact"
install -m 0755 "$dropbear_path" "${output_dir}/${dropbear_asset}"
install -m 0755 "$dropbearkey_path" "${output_dir}/${dropbearkey_asset}"
install -m 0755 "$dropbear_path" "${stage_dir}/${asset}/liskov-dropbear"
install -m 0755 "$dropbearkey_path" "${stage_dir}/${asset}/liskov-dropbearkey"
install -m 0644 README.md LICENSE "${stage_dir}/${asset}/"

tar \
  --format=ustar \
  --sort=name \
  --mtime='@0' \
  --owner=0 \
  --group=0 \
  --numeric-owner \
  -C "$stage_dir" \
  -cf - \
  "$asset" |
  gzip -n -9 >"${output_dir}/${archive}"

binary_sha256=$(sha256sum "${output_dir}/${asset}" | cut -d ' ' -f 1)
archive_sha256=$(sha256sum "${output_dir}/${archive}" | cut -d ' ' -f 1)
dropbear_sha256=$(sha256sum "${output_dir}/${dropbear_asset}" | cut -d ' ' -f 1)
dropbearkey_sha256=$(sha256sum "${output_dir}/${dropbearkey_asset}" | cut -d ' ' -f 1)
binary_size=$(wc -c <"${output_dir}/${asset}" | tr -d ' ')
archive_size=$(wc -c <"${output_dir}/${archive}" | tr -d ' ')
dropbear_size=$(wc -c <"${output_dir}/${dropbear_asset}" | tr -d ' ')
dropbearkey_size=$(wc -c <"${output_dir}/${dropbearkey_asset}" | tr -d ' ')

jq -n \
  --arg tag "$tag" \
  --arg version "$version" \
  --arg sourceCommit "$source_commit" \
  --arg target "$target" \
  --arg binaryAsset "$asset" \
  --arg binarySha256 "$binary_sha256" \
  --argjson binaryByteSize "$binary_size" \
  --arg archiveAsset "$archive" \
  --arg archiveSha256 "$archive_sha256" \
  --argjson archiveByteSize "$archive_size" \
  --arg dropbearVersion "$dropbear_version" \
  --arg dropbearAsset "$dropbear_asset" \
  --arg dropbearSha256 "$dropbear_sha256" \
  --argjson dropbearByteSize "$dropbear_size" \
  --arg dropbearkeyAsset "$dropbearkey_asset" \
  --arg dropbearkeySha256 "$dropbearkey_sha256" \
  --argjson dropbearkeyByteSize "$dropbearkey_size" \
  '{
    schema: "proof.liskov.runtime-contact-release",
    schemaVersion: 2,
    contractEpoch: 1,
    runtimeBootstrapDomain: "proof.liskov.runtime-bootstrap-request.v2",
    tag: $tag,
    version: $version,
    sourceCommit: $sourceCommit,
    target: $target,
    binary: {
      asset: $binaryAsset,
      sha256: $binarySha256,
      byteSize: $binaryByteSize
    },
    archive: {
      asset: $archiveAsset,
      sha256: $archiveSha256,
      byteSize: $archiveByteSize
    },
    toolchain: {
      dropbearVersion: $dropbearVersion,
      dropbear: {
        asset: $dropbearAsset,
        sha256: $dropbearSha256,
        byteSize: $dropbearByteSize
      },
      dropbearkey: {
        asset: $dropbearkeyAsset,
        sha256: $dropbearkeySha256,
        byteSize: $dropbearkeyByteSize
      }
    }
  }' >"${output_dir}/runtime-contact-release.json"

(
  cd "$output_dir"
  sha256sum "$asset" "$archive" "$dropbear_asset" "$dropbearkey_asset" runtime-contact-release.json >SHA256SUMS
)

rm -rf "$stage_dir"
