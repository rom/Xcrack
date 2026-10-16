#!/usr/bin/env bash
# Cross-validate the `xcrack hashline` emitters against a REAL cracker: emit a
# hash line for a known-password file, then have hashcat crack it and confirm it
# recovers the password. This proves the emitted $office$/$pdf$ strings are
# exactly what hashcat expects.
#
# Not run in CI (hashcat + an OpenCL backend are not installed there). Locally:
#   sudo apt-get install -y hashcat pocl-opencl-icd qpdf   # pocl = CPU OpenCL
#   scripts/hashcat-xval.sh
#
# Requires: hashcat (with any backend device), qpdf, go.
set -euo pipefail

pw="hashcat"               # hashcat's canonical example password
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
export HOME="$work"        # hashcat writes session/potfiles under $HOME
root="$(cd "$(dirname "$0")/.." && pwd)"

go build -o "$work/xcrack" ./xcrack/cmd/xcrack
printf 'wrong1\n%s\nwrong2\n' "$pw" > "$work/wl.txt"

pass=0 fail=0
crack() { # <mode> <hashfile> <label>
  local mode="$1" hf="$2" label="$3" out="$work/out.$3"
  rm -f "$out"
  hashcat -m "$mode" -a 0 --quiet --potfile-disable --outfile "$out" \
    --outfile-format 2 "$hf" "$work/wl.txt" >/dev/null 2>&1 || true
  if [ "$(cat "$out" 2>/dev/null)" = "$pw" ]; then
    echo "PASS  $label (-m $mode): hashcat recovered '$pw'"; pass=$((pass+1))
  else
    echo "FAIL  $label (-m $mode): not recovered"; fail=$((fail+1))
  fi
}

# --- Office (agile, SHA-512/AES-256 -> 2013 / -m 9600) ---
cat > "$work/genoffice.go" <<'GO'
package main
import ("os"; ooxml "github.com/rom/xfileformats/formats/ooxml")
func main() {
	b, err := ooxml.BuildEncryptedAgile([]byte("hashcat"), []byte("PK\x03\x04 inner"), 100000)
	if err != nil { panic(err) }
	os.WriteFile(os.Args[1], b, 0o644)
}
GO
(cd "$root" && go run "$work/genoffice.go" "$work/office.bin")
"$work/xcrack" hashline "$work/office.bin" 2>/dev/null > "$work/office.hash"
crack 9600 "$work/office.hash" office2013

# --- PDF (RC4-128 -> -m 10500, AES-256/R6 -> -m 10700) ---
cat > "$work/genpdf.go" <<'GO'
package main
import ("bytes"; "fmt"; "os")
func main() {
	c := "BT /F1 24 Tf 72 700 Td (xval) Tj ET"
	objs := []string{"<< /Type /Catalog /Pages 2 0 R >>","<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
		"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>",
		fmt.Sprintf("<< /Length %d >>\nstream\n%s\nendstream", len(c), c)}
	var b bytes.Buffer; b.WriteString("%PDF-1.4\n"); off := make([]int, len(objs)+1)
	for i, o := range objs { off[i+1] = b.Len(); fmt.Fprintf(&b, "%d 0 obj %s endobj\n", i+1, o) }
	x := b.Len(); fmt.Fprintf(&b, "xref\n0 %d\n0000000000 65535 f \n", len(objs)+1)
	for i := 1; i <= len(objs); i++ { fmt.Fprintf(&b, "%010d 00000 n \n", off[i]) }
	fmt.Fprintf(&b, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(objs)+1, x)
	os.WriteFile(os.Args[1], b.Bytes(), 0o644)
}
GO
(cd "$root" && go run "$work/genpdf.go" "$work/plain.pdf")
qpdf --allow-weak-crypto --encrypt "$pw" "$pw" 128 --use-aes=n -- "$work/plain.pdf" "$work/rc4.pdf"
qpdf --encrypt "$pw" "$pw" 256 -- "$work/plain.pdf" "$work/aes.pdf"
"$work/xcrack" hashline "$work/rc4.pdf" 2>/dev/null > "$work/rc4.hash"
"$work/xcrack" hashline "$work/aes.pdf" 2>/dev/null > "$work/aes.hash"
crack 10500 "$work/rc4.hash" pdf-rc4-128
crack 10700 "$work/aes.hash" pdf-aes-256

echo "----"
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
