#!/usr/bin/env bash
# Run every Fuzz* target in the workspace for a bounded time. Usage:
#   scripts/fuzz.sh [duration]     e.g. scripts/fuzz.sh 30s   (default 20s each)
# Any crasher is written to the package's testdata/fuzz/<Fuzz>/ and must be
# committed as a regression seed. On failure the offending target(s) are named
# in a summary at the end (and, under GitHub Actions, in the job step summary),
# so a red run points straight at the target instead of a wall of fuzz output.
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
  ./xfileformats/formats/sshkey
  ./xfileformats/formats/privkey
  ./xfileformats/formats/iwork
  ./xfileformats/formats/keepass
  ./xcrack/pkg/xcrack
)
failed=()
for pkg in "${pkgs[@]}"; do
  for fn in $(go test -list '^Fuzz' "$pkg" 2>/dev/null | grep '^Fuzz' || true); do
    echo "== fuzz $pkg $fn ($dur) =="
    if ! go test -run '^$' -fuzz "^${fn}$" -fuzztime "$dur" "$pkg"; then
      failed+=("$pkg $fn")
    fi
  done
done

if [ ${#failed[@]} -eq 0 ]; then
  exit 0
fi

# Name the failing target(s) so the cause is obvious without scrolling the log.
echo
echo "== FUZZ FAILURES (${#failed[@]}) =="
printf '  %s\n' "${failed[@]}"
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  {
    echo "### Failing fuzz targets"
    printf '-  \`%s\`\n' "${failed[@]}"
  } >> "$GITHUB_STEP_SUMMARY"
fi
exit 1
