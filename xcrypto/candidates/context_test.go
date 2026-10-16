package candidates

import (
	"io"
	"reflect"
	"testing"
)

func TestFromName(t *testing.T) {
	cases := []struct {
		name string
		want []string
	}{
		{"invoice_2024.pdf.zip", []string{"invoice_2024.pdf", "invoice", "2024", "pdf", "invoice2024pdf"}},
		{"Secret-Report.docx", []string{"Secret-Report", "Secret", "Report", "SecretReport"}},
		{"path/to/backup2023.7z", []string{"backup2023", "2023"}},
		{"archive.zip!/inner Document.pdf", []string{"inner Document", "inner", "Document", "innerDocument"}},
		{"nodots", []string{"nodots"}},
	}
	for _, c := range cases {
		got := FromName(c.name)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("FromName(%q) = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestFromNameDedup(t *testing.T) {
	// "pass" appears as stem and only token; must not repeat.
	got := FromName("pass")
	if len(got) != 1 || got[0] != "pass" {
		t.Errorf("FromName(pass) = %v, want [pass]", got)
	}
}

func TestFromText(t *testing.T) {
	cases := []struct {
		text string
		want []string
	}{
		{"The password is Hunter2 for the archive.", []string{"Hunter2"}},
		{"password: s3cr3t!", []string{"s3cr3t"}},
		{`Use the passphrase "correct horse battery staple" to open.`, []string{"correct horse battery staple"}},
		{"pwd=letmein and pin 4321", []string{"letmein", "4321"}},
		{"no hints here", nil},
		{"PASSWORD => OpenSesame", []string{"OpenSesame"}},
	}
	for _, c := range cases {
		got := FromText([]byte(c.text), 0)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("FromText(%q) = %v, want %v", c.text, got, c.want)
		}
	}
}

func TestFromTextMax(t *testing.T) {
	text := []byte("password one password two password three password four")
	// Each "password X" yields the following token.
	got := FromText(text, 2)
	if len(got) != 2 {
		t.Errorf("FromText max=2 returned %d candidates: %v", len(got), got)
	}
}

func TestFromTextLongTokenSkipped(t *testing.T) {
	long := make([]byte, 0, 200)
	long = append(long, []byte("password ")...)
	for i := 0; i < 120; i++ {
		long = append(long, 'a')
	}
	got := FromText(long, 0)
	if len(got) != 0 {
		t.Errorf("FromText should skip >64-byte token, got %v", got)
	}
}

func TestContextSource(t *testing.T) {
	src := Context("secret.zip", []byte("the password is swordfish"), 0)
	var got []string
	for {
		b, err := src.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, string(b))
	}
	want := []string{"secret", "swordfish"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Context = %v, want %v", got, want)
	}
}

func TestDigitRuns(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"abc123def456", []string{"123", "456"}},
		{"2024", []string{"2024"}},
		{"nodigits", nil},
		{"1a2b3c", []string{"1", "2", "3"}},
	}
	for _, c := range cases {
		got := digitRuns(c.in)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("digitRuns(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}
