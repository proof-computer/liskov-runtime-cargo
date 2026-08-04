#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "usage: $0 <dropbear-source-archive> <output-dir>" >&2
  exit 2
fi

archive=$1
output_dir=$2
version=2026.94
expected_sha256=e098034a843699200c8c977a991fff73159735bf795d5f72ef672c41a6b1ae81

if [ ! -s "$archive" ]; then
  echo "Dropbear source archive is missing or empty" >&2
  exit 2
fi
actual_sha256=$(sha256sum "$archive" | cut -d ' ' -f 1)
if [ "$actual_sha256" != "$expected_sha256" ]; then
  echo "Dropbear source archive digest mismatch" >&2
  exit 2
fi

build_root=$(mktemp -d)
trap 'rm -rf "$build_root"' EXIT
tar -xjf "$archive" -C "$build_root"
source_dir="${build_root}/dropbear-${version}"

(
  cd "$source_dir"
  # Configure must see the static mode before its hardening probes so it skips
  # PIE flags; setting STATIC only at make time leaves a PT_INTERP segment.
  # Keep syslog support compiled so the fixed runtime invocation can use -E
  # to route Dropbear diagnostics exclusively to its supervised stderr.
  CC=musl-gcc ./configure \
    --enable-static \
    --disable-zlib \
    --disable-lastlog \
    --disable-utmp \
    --disable-utmpx \
    --disable-wtmp \
    --disable-wtmpx \
    --disable-loginfunc \
    --disable-pam \
    --disable-shadow
  make -j2 PROGRAMS="dropbear dropbearkey" STATIC=1
)

for artifact in "${source_dir}/dropbear" "${source_dir}/dropbearkey"; do
  if readelf -l "$artifact" | grep -q 'Requesting program interpreter'; then
    echo "Dropbear artifact unexpectedly contains a dynamic interpreter" >&2
    exit 1
  fi
done

mkdir -p "$output_dir"
install -m 0755 "${source_dir}/dropbear" "${output_dir}/liskov-dropbear"
install -m 0755 "${source_dir}/dropbearkey" "${output_dir}/liskov-dropbearkey"
