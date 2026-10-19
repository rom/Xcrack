package cluster

import (
	stdzip "archive/zip"
	"bytes"
	"compress/flate"
	"context"
	"crypto/rand"
	"encoding/binary"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/rom/xcrack/pkg/api"
	"github.com/rom/xcrack/pkg/xcrack"
	"github.com/rom/xcrypto/candidates"
	"github.com/rom/xcrypto/scheme/winzipaes"
)

// --- a real xcrackd fleet, in-process ---

func startFleet(t *testing.T, n int) []Server {
	t.Helper()
	servers := make([]Server, 0, n)
	for i := 0; i < n; i++ {
		pool := xcrack.NewPool(xcrack.Options{Workers: 2})
		srv := api.NewServer(pool, api.Config{})
		ts := httptest.NewServer(srv.Handler())
		t.Cleanup(ts.Close)
		t.Cleanup(func() { pool.Close() })
		servers = append(servers, Server{URL: ts.URL})
	}
	return servers
}

// --- WinZip-AES fixture (same shape as the engine tests) ---

func buildWinZipAES(t *testing.T, password []byte, strength byte, name string, plain []byte) []byte {
	t.Helper()
	p := winzipaes.Params{Strength: strength, ActualMethod: 8, VendorVer: 2}
	salt := make([]byte, p.SaltLen())
	if _, err := rand.Read(salt); err != nil {
		t.Fatal(err)
	}
	var cbuf bytes.Buffer
	fw, _ := flate.NewWriter(&cbuf, flate.DefaultCompression)
	fw.Write(plain)
	fw.Close()
	raw, err := winzipaes.EncryptRaw(password, p, salt, cbuf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	zw := stdzip.NewWriter(&b)
	fh := &stdzip.FileHeader{Name: name, Method: 99}
	fh.Flags |= 0x1
	fh.UncompressedSize64 = uint64(len(plain))
	fh.CompressedSize64 = uint64(len(raw))
	e := make([]byte, 0, 11)
	e = binary.LittleEndian.AppendUint16(e, 0x9901)
	e = binary.LittleEndian.AppendUint16(e, 7)
	e = binary.LittleEndian.AppendUint16(e, p.VendorVer)
	e = binary.LittleEndian.AppendUint16(e, winzipaes.VendorAE)
	e = append(e, p.Strength)
	e = binary.LittleEndian.AppendUint16(e, p.ActualMethod)
	fh.Extra = e
	w, _ := zw.CreateRaw(fh)
	w.Write(raw)
	zw.Close()
	return b.Bytes()
}

// candidateList makes a source of many wrong passwords with the real one buried
// in the middle, so the hit lands in some server's batch, not the first.
func candidateList(real string, n int) func() candidates.Source {
	words := make([]string, 0, n+1)
	for i := 0; i < n; i++ {
		words = append(words, "wrong-"+string(rune('a'+i%26))+itoa(i))
	}
	words = append(words[:n/2], append([]string{real}, words[n/2:]...)...)
	return func() candidates.Source { return candidates.Explicit(words...) }
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [20]byte
	p := len(b)
	for i > 0 {
		p--
		b[p] = byte('0' + i%10)
		i /= 10
	}
	return string(b[p:])
}

// TestCollectiveCracksOneFile proves a fleet of servers splits one file's
// keyspace and the first worker with the right batch recovers the password.
func TestCollectiveCracksOneFile(t *testing.T) {
	servers := startFleet(t, 3)
	const pw = "Welcome1"
	data := buildWinZipAES(t, []byte(pw), 3, "doc.bin", []byte("secret payload"))
	job := FileJob{Path: "doc.zip", Data: data, Candidates: candidateList(pw, 200)}

	res := Run(context.Background(), servers, []FileJob{job},
		Options{Mode: Collective, BatchSize: 8, PerRequest: 30 * time.Second})
	if len(res) != 1 {
		t.Fatalf("got %d results, want 1", len(res))
	}
	if res[0].Err != nil {
		t.Fatalf("err: %v", res[0].Err)
	}
	if !res[0].Found || res[0].Password != pw {
		t.Fatalf("got found=%v pw=%q, want true/%q", res[0].Found, res[0].Password, pw)
	}
}

// TestCollectiveNoHit proves an exhausted keyspace with no match returns cleanly
// (not found, no error).
func TestCollectiveNoHit(t *testing.T) {
	servers := startFleet(t, 2)
	data := buildWinZipAES(t, []byte("Welcome1"), 3, "doc.bin", []byte("x"))
	job := FileJob{Path: "doc.zip", Data: data, Candidates: func() candidates.Source {
		return candidates.Explicit("nope1", "nope2", "nope3", "nope4")
	}}
	res := Run(context.Background(), servers, []FileJob{job}, Options{Mode: Collective, BatchSize: 2})
	if res[0].Err != nil {
		t.Fatalf("unexpected err: %v", res[0].Err)
	}
	if res[0].Found {
		t.Fatalf("unexpected hit: %q", res[0].Password)
	}
}

// TestPartitionDifferentFiles proves Partition mode sends different files to
// different server groups and cracks them concurrently.
func TestPartitionDifferentFiles(t *testing.T) {
	// Two groups of one server each.
	fleet := startFleet(t, 2)
	servers := []Server{
		{URL: fleet[0].URL, Group: "g1"},
		{URL: fleet[1].URL, Group: "g2"},
	}
	dataA := buildWinZipAES(t, []byte("alpha99"), 3, "a.bin", []byte("A"))
	dataB := buildWinZipAES(t, []byte("beta42"), 1, "b.bin", []byte("B"))
	jobs := []FileJob{
		{Path: "a.zip", Data: dataA, Candidates: candidateList("alpha99", 60)},
		{Path: "b.zip", Data: dataB, Candidates: candidateList("beta42", 60)},
	}
	res := Run(context.Background(), servers, jobs, Options{Mode: Partition, BatchSize: 8})
	if res[0].Password != "alpha99" {
		t.Errorf("file A: got %q, want alpha99 (found=%v err=%v)", res[0].Password, res[0].Found, res[0].Err)
	}
	if res[1].Password != "beta42" {
		t.Errorf("file B: got %q, want beta42 (found=%v err=%v)", res[1].Password, res[1].Found, res[1].Err)
	}
}

// TestNoServers reports an error per job rather than panicking.
func TestNoServers(t *testing.T) {
	res := Run(context.Background(), nil, []FileJob{{Path: "x"}}, Options{})
	if res[0].Err == nil {
		t.Fatal("expected an error with no servers")
	}
}

// TestCollectiveResumeSkips proves ResumeOffsets skips an already-tried prefix:
// with the offset set past the password's position the fleet does NOT find it,
// while the same job with no offset does. This is the cross-run dedup / resume
// "brain".
func TestCollectiveResumeSkips(t *testing.T) {
	servers := startFleet(t, 3)
	const pw = "Welcome1"
	data := buildWinZipAES(t, []byte(pw), 3, "doc.bin", []byte("secret payload"))
	mk := func() FileJob {
		return FileJob{Path: "doc.zip", Data: data, Candidates: candidateList(pw, 200)}
	}
	// Password is injected at index 100; skipping 150 must miss it.
	res := Run(context.Background(), servers, []FileJob{mk()},
		Options{Mode: Collective, BatchSize: 8, ResumeOffsets: map[string]int64{"doc.zip": 150}})
	if res[0].Err != nil {
		t.Fatalf("err: %v", res[0].Err)
	}
	if res[0].Found {
		t.Fatalf("resume offset 150 should have skipped the password at index 100, but found %q", res[0].Password)
	}
	// Control: no offset finds it, confirming the fixture is otherwise crackable.
	ctl := Run(context.Background(), servers, []FileJob{mk()}, Options{Mode: Collective, BatchSize: 8})
	if !ctl[0].Found || ctl[0].Password != pw {
		t.Fatalf("control run should find %q, got found=%v pw=%q", pw, ctl[0].Found, ctl[0].Password)
	}
}

// TestCollectiveResumeOffsetContiguous checks Progress.Tried (the safe resume
// offset) never exceeds the keyspace and reaches it on a fully-exhausted no-hit
// run, so persisting it cannot skip untried candidates.
func TestCollectiveResumeOffsetContiguous(t *testing.T) {
	servers := startFleet(t, 3)
	data := buildWinZipAES(t, []byte("Welcome1"), 3, "doc.bin", []byte("secret payload"))
	const keyspace = 120
	job := FileJob{Path: "doc.zip", Data: data, Candidates: candidateList("not-present-anywhere", keyspace)}
	// OnProgress is called concurrently (one goroutine per server), so the
	// callback must synchronize its own state.
	var mu sync.Mutex
	var maxTried int64
	res := Run(context.Background(), servers, []FileJob{job}, Options{
		Mode: Collective, BatchSize: 8,
		OnProgress: func(p Progress) {
			mu.Lock()
			if p.Tried > maxTried {
				maxTried = p.Tried
			}
			mu.Unlock()
		},
	})
	if res[0].Found {
		t.Fatal("unexpected hit")
	}
	// keyspace+1 because candidateList inserts the (absent) real word too.
	if maxTried > keyspace+1 {
		t.Errorf("Tried=%d exceeded keyspace=%d (would skip untried candidates on resume)", maxTried, keyspace+1)
	}
	if maxTried != keyspace+1 {
		t.Errorf("exhausted run Tried=%d, want %d (full contiguous confirmation)", maxTried, keyspace+1)
	}
}
