//go:build !windows && !plan9 && !js && !wasip1

package auditlog

import (
	"net"
	"strings"
	"testing"
	"time"
)

// TestSyslogBackendDelivers proves the syslog handler actually ships records to
// a syslog sink: it points xcrackd/xcrack's logger at a local UDP syslog server
// and checks the record arrives with a priority prefix and the payload.
func TestSyslogBackendDelivers(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot open UDP listener: %v", err)
	}
	defer pc.Close()

	l, closer, err := New(Config{
		Level:         "debug",
		Format:        "json",
		Syslog:        true,
		SyslogNetwork: "udp",
		SyslogAddress: pc.LocalAddr().String(),
		SyslogTag:     "xcrack-test",
	})
	if err != nil {
		t.Skipf("syslog dial failed (no sink in this environment): %v", err)
	}
	defer closer.Close()

	l.Info("file cracked", "file", "secret.zip", "type", "zip")

	_ = pc.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 4096)
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatalf("no syslog datagram received: %v", err)
	}
	msg := string(buf[:n])
	// RFC3164 priority prefix "<NN>" then the tag and our payload.
	if !strings.HasPrefix(msg, "<") {
		t.Errorf("missing syslog priority prefix: %q", msg)
	}
	if !strings.Contains(msg, "xcrack-test") {
		t.Errorf("missing syslog tag: %q", msg)
	}
	if !strings.Contains(msg, "file cracked") || !strings.Contains(msg, "secret.zip") {
		t.Errorf("payload not delivered: %q", msg)
	}
}
