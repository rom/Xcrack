package xcrack

import (
	stdzip "archive/zip"
	"bytes"
	"context"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/rom/xcrack/pkg/xcrack/candidates"
)

func zipBin(t *testing.T) string {
	t.Helper()
	p, err := exec.LookPath("zip")
	if err != nil {
		t.Skip("zip CLI not available")
	}
	return p
}

func runZip(t *testing.T, zipPath, password, out string, inputs ...string) {
	t.Helper()
	args := []string{"-j", "-P", password, out}
	args = append(args, inputs...)
	cmd := exec.Command(zipPath, args...)
	if o, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("zip failed: %v\n%s", err, o)
	}
}

func findLeaf(root *Node, name string) *Node {
	var found *Node
	root.Walk(func(n *Node) {
		if found == nil && n.Leaf() && n.Content != nil && filepath.Base(n.Path) == name {
			found = n
		}
	})
	return found
}

func readContent(t *testing.T, n *Node) []byte {
	t.Helper()
	rc, err := n.Content.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	b, err := readAllRC(rc)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func readAllRC(rc interface{ Read([]byte) (int, error) }) ([]byte, error) {
	var buf bytes.Buffer
	tmp := make([]byte, 4096)
	for {
		n, err := rc.Read(tmp)
		if n > 0 {
			buf.Write(tmp[:n])
		}
		if err != nil {
			if err.Error() == "EOF" {
				return buf.Bytes(), nil
			}
			return buf.Bytes(), err
		}
	}
}

// TestNestedEncryptedZip: encrypted ZIP -> encrypted ZIP -> text, with distinct
// passwords. Verifies full decomposition, per-node password+content, and
// Passwords().
func TestNestedEncryptedZip(t *testing.T) {
	zb := zipBin(t)
	dir := t.TempDir()
	secret := []byte("the real payload the scanner must analyse\n")
	secretPath := filepath.Join(dir, "secret.txt")
	if err := os.WriteFile(secretPath, secret, 0o600); err != nil {
		t.Fatal(err)
	}
	innerPath := filepath.Join(dir, "inner.zip")
	runZip(t, zb, "innerpass", innerPath, secretPath)
	outerPath := filepath.Join(dir, "outer.zip")
	runZip(t, zb, "outerpass", outerPath, innerPath)
	data, err := os.ReadFile(outerPath)
	if err != nil {
		t.Fatal(err)
	}

	src := candidates.Explicit("nope", "outerpass", "innerpass", "alsono")
	res, err := Process(context.Background(), bytes.NewReader(data), int64(len(data)), src, Options{})
	if err != nil {
		t.Fatal(err)
	}

	if res.Root.Format != "zip" {
		t.Fatalf("root format = %q, want zip", res.Root.Format)
	}
	leaf := findLeaf(res.Root, "secret.txt")
	if leaf == nil {
		t.Fatalf("secret.txt leaf not found; tree:\n%s", dumpTree(res.Root))
	}
	if leaf.Status != StatusDecrypted {
		t.Errorf("leaf status = %v, want decrypted", leaf.Status)
	}
	if leaf.Password != "innerpass" {
		t.Errorf("leaf password = %q, want innerpass", leaf.Password)
	}
	if got := readContent(t, leaf); !bytes.Equal(got, secret) {
		t.Errorf("leaf content mismatch:\n got %q\nwant %q", got, secret)
	}
	pws := res.Root // check Passwords() via result
	_ = pws
	got := map[string]bool{}
	for _, p := range res.Passwords() {
		got[p] = true
	}
	if !got["innerpass"] || !got["outerpass"] {
		t.Errorf("Passwords() = %v, want to include innerpass and outerpass", res.Passwords())
	}
	if res.Stats.FilesSeen != 3 {
		t.Errorf("FilesSeen = %d, want 3", res.Stats.FilesSeen)
	}
}

// TestPasswordPromotion: when inner and outer share a password, promotion makes
// the inner layer hit on the first try instead of rescanning the wordlist.
func TestPasswordPromotion(t *testing.T) {
	zb := zipBin(t)
	dir := t.TempDir()
	secret := []byte("shared-password payload\n")
	secretPath := filepath.Join(dir, "s.txt")
	os.WriteFile(secretPath, secret, 0o600)
	innerPath := filepath.Join(dir, "in.zip")
	runZip(t, zb, "sharedpw", innerPath, secretPath)
	outerPath := filepath.Join(dir, "out.zip")
	runZip(t, zb, "sharedpw", outerPath, innerPath)
	data, _ := os.ReadFile(outerPath)

	// wordlist with the real password last, so position matters
	words := []string{"a", "b", "c", "d", "e", "f", "g", "sharedpw"}

	run := func(promote bool) int64 {
		src := candidates.Explicit(words...)
		res, err := Process(context.Background(), bytes.NewReader(data), int64(len(data)), src, Options{
			Workers:   1, // deterministic candidate counting
			NoPromote: !promote,
		})
		if err != nil {
			t.Fatal(err)
		}
		return res.Stats.CandidatesTried
	}
	withPromo := run(true)
	withoutPromo := run(false)
	if withPromo >= withoutPromo {
		t.Errorf("promotion did not reduce work: with=%d without=%d", withPromo, withoutPromo)
	}
	t.Logf("candidates tried: with promotion=%d, without=%d", withPromo, withoutPromo)
}

// TestDepthLimit: a deeply nested (plaintext) zip is pruned at MaxDepth.
func TestDepthLimit(t *testing.T) {
	data := []byte("leaf")
	for i := 0; i < 6; i++ {
		data = wrapPlainZip(t, "layer.zip", data)
	}
	res, err := Process(context.Background(), bytes.NewReader(data), int64(len(data)),
		candidates.Explicit(), Options{Limits: Limits{MaxDepth: 2}})
	if err != nil {
		t.Fatal(err)
	}
	var sawLimit bool
	res.Root.Walk(func(n *Node) {
		if n.Status == StatusLimitExceeded {
			sawLimit = true
		}
	})
	if !sawLimit {
		t.Fatalf("expected a limit-exceeded node at MaxDepth=2; tree:\n%s", dumpTree(res.Root))
	}
}

// TestHostileInput: random/garbage/truncated input must never panic and must
// return a result.
func TestHostileInput(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 200; i++ {
		n := rng.Intn(2048)
		buf := make([]byte, n)
		rng.Read(buf)
		// sometimes prefix with the zip magic to drive the zip parser on garbage
		if i%3 == 0 && n >= 4 {
			copy(buf, []byte("PK\x03\x04"))
		}
		res, err := Process(context.Background(), bytes.NewReader(buf), int64(len(buf)),
			candidates.Explicit("x"), Options{})
		if err != nil {
			continue // run-level errors are acceptable; a panic is not
		}
		if res == nil || res.Root == nil {
			t.Fatalf("nil result for input %d", i)
		}
	}
}

// --- test helpers ---

func wrapPlainZip(t *testing.T, name string, inner []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	zw := stdzip.NewWriter(&b)
	w, err := zw.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(inner); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func dumpTree(n *Node) string {
	var b bytes.Buffer
	var walk func(*Node, int)
	walk = func(n *Node, d int) {
		for i := 0; i < d; i++ {
			b.WriteString("  ")
		}
		b.WriteString(n.Path)
		b.WriteString(" [")
		b.WriteString(n.Format)
		b.WriteString(" ")
		b.WriteString(n.Status.String())
		if n.WasEncrypted {
			b.WriteString(" pw=" + n.Password)
		}
		if n.Err != nil {
			b.WriteString(" err=" + n.Err.Error())
		}
		b.WriteString("]\n")
		for _, c := range n.Children {
			walk(c, d+1)
		}
	}
	walk(n, 0)
	return b.String()
}
