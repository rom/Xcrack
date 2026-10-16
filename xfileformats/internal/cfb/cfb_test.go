package cfb

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"
)

func TestBuildOpenRoundTrip(t *testing.T) {
	small := []byte("EncryptionInfo: a small stream that lives in the mini-FAT")
	large := bytes.Repeat([]byte("EncryptedPackage segment "), 400) // > 4096 => regular FAT
	data := Build([]StreamEntry{
		{Name: "EncryptionInfo", Data: small},
		{Name: "EncryptedPackage", Data: large},
	})
	if !IsCFB(data) {
		t.Fatal("Build output is not recognized as CFB")
	}
	f, err := Open(data)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	gotSmall, ok := f.Stream("EncryptionInfo")
	if !ok || !bytes.Equal(gotSmall, small) {
		t.Fatalf("EncryptionInfo mismatch: ok=%v len=%d want=%d", ok, len(gotSmall), len(small))
	}
	gotLarge, ok := f.Stream("EncryptedPackage")
	if !ok || !bytes.Equal(gotLarge, large) {
		t.Fatalf("EncryptedPackage mismatch: ok=%v len=%d want=%d", ok, len(gotLarge), len(large))
	}
}

func TestOpenRejectsGarbage(t *testing.T) {
	if _, err := Open([]byte("not a compound file at all, really")); err == nil {
		t.Fatal("expected error for non-CFB input")
	}
	if _, err := Open(make([]byte, 600)); err == nil {
		t.Fatal("expected error for zero header")
	}
}

// difatBomb builds the smallest CFB header whose DIFAT sector chain claims a
// near-maximal numDIFAT (~4e9) and loops back on itself. Before the walk was
// bounded by the file's physical sector count, Open followed numDIFAT and grew
// its FAT-sector list without bound, hanging and exhausting memory. (Regression
// for the fuzzer-found FuzzOpen crasher.)
func difatBomb() []byte {
	b := make([]byte, 1024) // header (512) + one data sector
	copy(b, sig)
	binary.LittleEndian.PutUint16(b[30:], 9)          // 512-byte sectors
	binary.LittleEndian.PutUint16(b[32:], 6)          // 64-byte mini sectors
	binary.LittleEndian.PutUint32(b[48:], endOfChain) // no directory chain
	binary.LittleEndian.PutUint32(b[68:], 0)          // firstDIFAT -> sector 0
	binary.LittleEndian.PutUint32(b[72:], 0xFFFFFFFE) // numDIFAT (near-max)
	binary.LittleEndian.PutUint32(b[1020:], 0)        // sector 0 points at itself
	return b
}

func TestOpenRejectsDIFATBomb(t *testing.T) {
	done := make(chan error, 1)
	go func() {
		_, err := Open(difatBomb())
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected error for oversized/cyclic DIFAT chain")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Open did not return: DIFAT sector-chain walk is unbounded")
	}
}
