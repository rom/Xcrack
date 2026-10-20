package webui

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/smtp"
	"strings"
	"time"
)

// Out-of-band job-finished notifications, beyond the per-viewer browser toast:
// an operator-configured webhook (a JSON POST) and/or an SMTP email, fired once
// when a job reaches a terminal state. Both targets are set by the operator, not
// by a request, so neither is an SSRF vector the end user controls. Delivery is
// best-effort and asynchronous: a slow or failing target never blocks or fails a
// job.

// NotifyConfig configures the out-of-band notifiers. Any empty field disables
// that channel.
type NotifyConfig struct {
	// WebhookURL receives an HTTP POST with a JSON job summary on each finish.
	WebhookURL string
	// SMTP* configure email. SMTPHost (host:port) and at least one SMTPTo enable
	// it; SMTPUser/SMTPPassword add PLAIN auth (over the server's TLS, typically
	// via a submission port behind a relay — this uses plain SMTP, so point it at
	// a local/relay MTA).
	SMTPHost     string
	SMTPFrom     string
	SMTPTo       []string
	SMTPUser     string
	SMTPPassword string
}

func (n NotifyConfig) enabled() bool {
	return n.WebhookURL != "" || (n.SMTPHost != "" && len(n.SMTPTo) > 0)
}

// notifier delivers job-finished notifications. It is created only when at least
// one channel is configured.
type notifier struct {
	cfg  NotifyConfig
	send func(to []string, msg []byte) error // smtp.SendMail, overridable in tests
	post func(url, contentType string, body []byte) error
}

func newNotifier(cfg NotifyConfig) *notifier {
	if !cfg.enabled() {
		return nil
	}
	return &notifier{
		cfg: cfg,
		send: func(to []string, msg []byte) error {
			var auth smtp.Auth
			if cfg.SMTPUser != "" {
				host := cfg.SMTPHost
				if i := strings.LastIndex(host, ":"); i >= 0 {
					host = host[:i]
				}
				auth = smtp.PlainAuth("", cfg.SMTPUser, cfg.SMTPPassword, host)
			}
			return smtp.SendMail(cfg.SMTPHost, auth, cfg.SMTPFrom, to, msg)
		},
		post: func(url, ct string, body []byte) error {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
			if err != nil {
				return err
			}
			req.Header.Set("Content-Type", ct)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				return err
			}
			_ = resp.Body.Close()
			return nil
		},
	}
}

// jobFinished fires the configured notifications for a finished job
// asynchronously (best-effort; never blocks the caller).
func (n *notifier) jobFinished(v JobView) {
	if n == nil {
		return
	}
	go n.deliver(v)
}

// deliver sends the configured notifications synchronously.
func (n *notifier) deliver(v JobView) {
	if n == nil {
		return
	}
	if n.cfg.WebhookURL != "" {
		body, _ := json.Marshal(map[string]any{
			"event": "job_finished", "id": v.ID, "kind": v.Kind, "state": v.State,
			"decrypted": v.Decrypted, "files": v.Files, "ended_at": v.EndedAt,
		})
		_ = n.post(n.cfg.WebhookURL, "application/json", body)
	}
	if n.cfg.SMTPHost != "" && len(n.cfg.SMTPTo) > 0 {
		subject := fmt.Sprintf("xcrack job %s: %s", v.ID, v.State)
		msg := fmt.Sprintf("To: %s\r\nFrom: %s\r\nSubject: %s\r\n\r\n%s\r\n",
			strings.Join(n.cfg.SMTPTo, ", "), n.cfg.SMTPFrom, subject,
			fmt.Sprintf("Job %s (%s) finished: %s. Decrypted %d. Files: %s.",
				v.ID, kindLabel(v.Kind), v.State, v.Decrypted, strings.Join(v.Files, ", ")))
		_ = n.send(n.cfg.SMTPTo, []byte(msg))
	}
}

func kindLabel(k string) string {
	if k == "" {
		return "crack"
	}
	return k
}
