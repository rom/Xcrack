package access

import "testing"

func jetHeader(sig string, version byte) []byte {
	b := make([]byte, 128)
	copy(b[0:], []byte{0x00, 0x01, 0x00, 0x00})
	copy(b[4:], []byte(sig))
	b[headerVersionOffset] = version
	return b
}

func TestDetect(t *testing.T) {
	cases := []struct {
		name    string
		hdr     []byte
		want    bool
		variant string
	}{
		{"jet3", jetHeader("Standard Jet DB\x00", 0x00), true, "jet3"},
		{"jet4", jetHeader("Standard Jet DB\x00", 0x01), true, "jet4"},
		{"ace", jetHeader("Standard ACE DB\x00", 0x02), true, "ace"},
		{"not-access", []byte("PK\x03\x04 this is a zip file...."), false, ""},
		{"too-short", []byte("abc"), false, ""},
	}
	f := New()
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			conf, ok := f.Detect(c.hdr)
			if ok != c.want {
				t.Fatalf("Detect ok = %v, want %v", ok, c.want)
			}
			if ok && conf <= 0 {
				t.Errorf("confidence = %v, want > 0", conf)
			}
			if c.want {
				if v := Variant(c.hdr); v != c.variant {
					t.Errorf("Variant = %q, want %q", v, c.variant)
				}
			}
		})
	}
}

func TestName(t *testing.T) {
	if New().Name() != "access" {
		t.Fatal("Name should be access")
	}
}
