package webui

import (
	"strings"
	"testing"
)

func TestNotifierDelivers(t *testing.T) {
	n := newNotifier(NotifyConfig{
		WebhookURL: "http://hook.example/x",
		SMTPHost:   "mail.example:25", SMTPFrom: "xcrack@example", SMTPTo: []string{"ops@example", "sec@example"},
	})
	if n == nil {
		t.Fatal("notifier not created despite configured channels")
	}
	var gotURL string
	var gotBody []byte
	var gotTo []string
	var gotMsg []byte
	n.post = func(url, ct string, body []byte) error { gotURL, gotBody = url, body; return nil }
	n.send = func(to []string, msg []byte) error { gotTo, gotMsg = to, msg; return nil }

	n.deliver(JobView{ID: "abc123", Kind: "kp", State: StateDone, Decrypted: 2, Files: []string{"a", "b"}})

	if gotURL != "http://hook.example/x" {
		t.Fatalf("webhook url = %q", gotURL)
	}
	if !strings.Contains(string(gotBody), `"state":"done"`) || !strings.Contains(string(gotBody), `"id":"abc123"`) {
		t.Fatalf("webhook body = %s", gotBody)
	}
	if len(gotTo) != 2 {
		t.Fatalf("email recipients = %v, want 2", gotTo)
	}
	m := string(gotMsg)
	if !strings.Contains(m, "Subject: xcrack job abc123: done") || !strings.Contains(m, "Decrypted 2") {
		t.Fatalf("email message = %q", m)
	}
}

func TestNotifierDisabled(t *testing.T) {
	if n := newNotifier(NotifyConfig{}); n != nil {
		t.Fatal("notifier created with no channels configured")
	}
	// A nil notifier must be safe to call.
	var n *notifier
	n.jobFinished(JobView{})
}
