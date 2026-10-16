#!/usr/bin/env bash
# Run every Fuzz* target in the workspace for a bounded time. Usage:
#   scripts/fuzz.sh [duration]     e.g. scripts/fuzz.sh 30s   (default 20s each)
# Any crasher is written to the package's testdata/fuzz/<Fuzz>/ and must be
# committed as a regression seed.
set -euo pipefail
dur="${1:-20s}"
pkgs=(
  ./xcrypto/pattern
  ./xcrypto/scheme/ooxml
  ./xfileformats/internal/cfb
  ./xfileformats/formats/zip
  ./xfileformats/formats/ooxml
  ./xfileformats/formats/pdf
  ./xfileformats/formats/archive
  ./xfileformats/formats/odf
  ./xfileformats/formats/msoffice
  ./xfileformats/formats/age
  ./xfileformats/formats/pgp
  ./xcrack/pkg/xcrack
)
fail=0
for pkg in "${pkgs[@]}"; do
  for fn in $(go test -list '^Fuzz' "$pkg" 2>/dev/null | grep '^Fuzz' || true); do
    echo "== fuzz $pkg $fn ($dur) =="
    go test -run '^$' -fuzz "^${fn}$" -fuzztime "$dur" "$pkg" || fail=1
  done
done
exit $fail
