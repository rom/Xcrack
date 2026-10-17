package vbaproject

import (
	"archive/zip"
	"bytes"
	"testing"

	xvba "github.com/rom/xcrypto/scheme/vbaproject"
	"github.com/rom/xfileformats/internal/cfb"
)

// dpbHashed is the "basic" golden DPB from the independent Python oracle
// (research/vba_oracle.py): password "Welcome1", salt 0x11223344.
const dpbHashed = "A7A59B3FD4528F6F8F6F7091906F9EA2F39131587C65CDA11B80ED7C56150B6088C3209822962A"
const dpbPlain = "42405B59576557651BD4F405242303A305E10315" // password "LetMeIn2024"
const dpbNone = "080A282B292B292B"

func projectStream(dpb string) []byte {
	// A minimal PROJECT stream: the DPB line is what matters.
	return []byte("ID=\"{00000000-0000-0000-0000-000000000000}\"\r\n" +
		"DPB=\"" + dpb + "\"\r\n" +
		"GC=\"1E1C...\"\r\n")
}

func cfbWithProject(dpb string) []byte {
	return cfb.Build([]cfb.StreamEntry{
		{Name: "PROJECT", Data: projectStream(dpb)},
		{Name: "dir", Data: bytes.Repeat([]byte{0}, 32)},
	})
}

func TestParseProjectHashedCFB(t *testing.T) {
	data := cfbWithProject(dpbHashed)
	res, err := ParseProject(data)
	if err != nil {
		t.Fatalf("ParseProject: %v", err)
	}
	if res.Kind != xvba.KindHash {
		t.Fatalf("Kind=%v want KindHash", res.Kind)
	}
	// End-to-end through the Format: Probe → Verify.
	f := New()
	ch, err := f.Probe(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if ok, _, _ := f.Verify(ch, []byte("Welcome1")); !ok {
		t.Error("Verify(correct) = false")
	}
	if ok, _, _ := f.Verify(ch, []byte("wrong")); ok {
		t.Error("Verify(wrong) = true")
	}
}

func TestParseProjectPlaintextCFB(t *testing.T) {
	data := cfbWithProject(dpbPlain)
	f := New()
	ch, err := f.Probe(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if ch.Hint != "LetMeIn2024" {
		t.Errorf("Hint=%q want LetMeIn2024", ch.Hint)
	}
	if ok, _, _ := f.Verify(ch, []byte("LetMeIn2024")); !ok {
		t.Error("plaintext Verify(correct) = false")
	}
}

func TestParseProjectNone(t *testing.T) {
	data := cfbWithProject(dpbNone)
	res, err := ParseProject(data)
	if err != nil {
		t.Fatalf("ParseProject: %v", err)
	}
	if res.Kind != xvba.KindNone {
		t.Fatalf("Kind=%v want KindNone", res.Kind)
	}
	// A no-password project is not a crackable target: Probe declines it.
	if _, err := New().Probe(bytes.NewReader(data), int64(len(data))); err == nil {
		t.Error("Probe should decline a passwordless project")
	}
}

func TestParseProjectOOXMLZip(t *testing.T) {
	// A macro-enabled OOXML document: a zip whose word/vbaProject.bin is a CFB.
	vba := cfbWithProject(dpbHashed)
	var zbuf bytes.Buffer
	zw := zip.NewWriter(&zbuf)
	w, err := zw.Create("word/vbaProject.bin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(vba); err != nil {
		t.Fatal(err)
	}
	// A decoy part to prove selection works.
	w2, _ := zw.Create("word/document.xml")
	w2.Write([]byte("<xml/>"))
	zw.Close()

	res, err := ParseProject(zbuf.Bytes())
	if err != nil {
		t.Fatalf("ParseProject(ooxml): %v", err)
	}
	if res.Kind != xvba.KindHash {
		t.Fatalf("Kind=%v want KindHash", res.Kind)
	}
}

func TestDetectForceOnly(t *testing.T) {
	// Detect claims CFB and zip heads (it is only consulted when forced).
	if _, ok := New().Detect([]byte("\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1....")); !ok {
		t.Error("Detect should claim CFB when forced")
	}
	if _, ok := New().Detect([]byte("PK\x03\x04....")); !ok {
		t.Error("Detect should claim zip when forced")
	}
	if _, ok := New().Detect([]byte("not a compound file")); ok {
		t.Error("Detect should not claim arbitrary bytes")
	}
}
