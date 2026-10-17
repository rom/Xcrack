// Package auditlog builds the structured, audit-grade logger shared by the
// xcrack CLI and the xcrackd server.
//
// It wraps log/slog with three operator-facing knobs — level, output format
// (text or JSON) and destination (stderr, a file, or the system logger via
// syslog) — and turns the engine's per-node xcrack.AuditEvent stream into an
// audit trail that records what was seen and, for every successful crack, the
// filename, file type, status and time-to-crack. The recovered password is
// logged only when the operator opts in (IncludeSecrets), so the default trail
// is safe to ship to a central log host.
//
// The same logger carries the engine's ordinary diagnostic output (via Printf),
// so one --log-format / --syslog choice governs everything a run emits and the
// whole execution can be followed in one place.
package auditlog

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rom/xcrack/pkg/xcrack"
)

// Config selects the level, format and destination of the shared logger. The
// zero value logs at info level in text format to stderr.
type Config struct {
	// Level is debug|info|warn|error (case-insensitive). Empty means info.
	Level string
	// Format is "text" (default) or "json".
	Format string

	// File, when set and Syslog is false, appends structured log lines to this
	// path (created if absent, 0600). Empty logs to stderr.
	File string

	// Syslog, when true, sends log lines to the system logger instead of stderr
	// or File. It is supported on Unix-like systems only; New returns an error on
	// a platform without syslog support.
	Syslog bool
	// SyslogNetwork and SyslogAddress select a remote syslog sink ("udp"/"tcp"
	// and host:port). Both empty use the local syslog socket.
	SyslogNetwork string
	SyslogAddress string
	// SyslogTag is the syslog ident/tag. Empty uses the program name.
	SyslogTag string

	// IncludeSecrets controls whether the audit trail records recovered passwords.
	// It is off by default so the trail never persists a cleartext secret unless
	// the operator explicitly asks for it.
	IncludeSecrets bool
}

// New builds a *slog.Logger from cfg. The returned io.Closer releases the
// destination (a syslog connection or a log file); it is a no-op for stderr and
// is always safe to call. New returns an error only for an unusable destination
// (e.g. an unopenable file, or --syslog on a platform without syslog support).
func New(cfg Config) (*slog.Logger, io.Closer, error) {
	lvl := ParseLevel(cfg.Level)
	opts := &slog.HandlerOptions{Level: lvl}

	if cfg.Syslog {
		h, closer, err := newSyslogHandler(cfg, lvl)
		if err != nil {
			return nil, nil, err
		}
		return slog.New(h), closer, nil
	}

	var w io.Writer = os.Stderr
	var closer io.Closer = nopCloser{}
	if cfg.File != "" {
		f, err := os.OpenFile(cfg.File, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			return nil, nil, fmt.Errorf("open log file: %w", err)
		}
		w, closer = f, f
	}
	return slog.New(newHandler(w, cfg.Format, opts)), closer, nil
}

// newHandler builds a text or JSON slog handler writing to w.
func newHandler(w io.Writer, format string, opts *slog.HandlerOptions) slog.Handler {
	if strings.EqualFold(format, "json") {
		return slog.NewJSONHandler(w, opts)
	}
	return slog.NewTextHandler(w, opts)
}

// ParseLevel maps a level string to an slog.Level, defaulting to info.
func ParseLevel(level string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

type nopCloser struct{}

func (nopCloser) Close() error { return nil }

// defaultTag returns the running program's base name, used as the syslog tag
// when none is configured.
func defaultTag() string {
	if len(os.Args) > 0 && os.Args[0] != "" {
		return filepath.Base(os.Args[0])
	}
	return "xcrack"
}

// --- xcrack.Logger adapter ---------------------------------------------------

type printfLogger struct{ l *slog.Logger }

func (p printfLogger) Debugf(f string, a ...any) { p.l.Debug(fmt.Sprintf(f, a...)) }
func (p printfLogger) Infof(f string, a ...any)  { p.l.Info(fmt.Sprintf(f, a...)) }
func (p printfLogger) Warnf(f string, a ...any)  { p.l.Warn(fmt.Sprintf(f, a...)) }
func (p printfLogger) Errorf(f string, a ...any) { p.l.Error(fmt.Sprintf(f, a...)) }

// Printf adapts a *slog.Logger to the xcrack.Logger interface so the engine's
// diagnostic output flows to the same destination as the audit trail.
func Printf(l *slog.Logger) xcrack.Logger { return printfLogger{l} }

// --- audit trail -------------------------------------------------------------

// FileSummary is the headline audit view of one processed source file, folded
// from its whole result tree. It answers "was this file cracked, and how" with
// a single record even when the encryption lives in nested entries (a legacy
// .doc encrypts internal streams; a ZIP encrypts per entry), so the audit line
// names the top-level file type rather than a raw inner stream.
type FileSummary struct {
	Format       string        // top-level detected format (the "file type")
	Encrypted    bool          // any node in the tree required a password
	Cracked      bool          // any encrypted node was decrypted
	TimeToCrack  time.Duration // longest per-node crack time in the tree
	Size         int64         // root content size (0 if unknown)
	Passwords    []string      // recovered passwords, distinct, first-seen order
	KeyRecovered bool          // any node was unlocked by key recovery (no password)
	CrackedPaths []string      // lineage of each decrypted node (for nested archives)
}

// Summarize folds a result tree into a FileSummary.
func Summarize(res *xcrack.Result) FileSummary {
	var s FileSummary
	if res == nil || res.Root == nil {
		return s
	}
	s.Format = res.Root.Format
	if res.Root.Content != nil {
		s.Size = res.Root.Content.Size()
	}
	seen := map[string]bool{}
	res.Root.Walk(func(n *xcrack.Node) {
		if n.WasEncrypted {
			s.Encrypted = true
		}
		if n.WasEncrypted && n.Status == xcrack.StatusDecrypted {
			s.Cracked = true
			if n.CrackDuration > s.TimeToCrack {
				s.TimeToCrack = n.CrackDuration
			}
			if n.Path != "" {
				s.CrackedPaths = append(s.CrackedPaths, n.Path)
			}
			if n.KeyRecovered {
				s.KeyRecovered = true
			}
			if n.Password != "" && !seen[n.Password] {
				seen[n.Password] = true
				s.Passwords = append(s.Passwords, n.Password)
			}
		}
	})
	return s
}

// LogFile writes one headline audit record for a processed source file, plus a
// per-node debug trace of the whole tree so the execution can be followed with
// --log-level debug. The headline is logged at info "file cracked" when at least
// one encrypted node was recovered, otherwise at debug "file processed"; it
// always carries the filename, file type and (when cracked) the time-to-crack.
// The recovered password(s) are included only when includeSecrets is true. Any
// extra attrs (e.g. a client address) are attached to every record.
//
// name is the file's display name (the CLI passes the source basename); pass ""
// when there is none (an uploaded body), and the record omits a filename.
func LogFile(l *slog.Logger, name string, res *xcrack.Result, includeSecrets bool, extra ...slog.Attr) {
	if l == nil || res == nil || res.Root == nil {
		return
	}
	// Detailed per-node trace (debug) for following execution.
	if l.Enabled(context.Background(), slog.LevelDebug) {
		res.Root.Walk(func(n *xcrack.Node) {
			traceNode(l, n.AuditEvent(includeSecrets), extra)
		})
	}

	s := Summarize(res)
	if name == "" {
		name = res.Root.Path
	}
	attrs := make([]slog.Attr, 0, 10+len(extra))
	attrs = append(attrs,
		slog.String("file", name),
		slog.String("type", s.Format),
		slog.Bool("encrypted", s.Encrypted),
		slog.Bool("cracked", s.Cracked),
		slog.Int64("size", s.Size),
	)
	if s.Cracked {
		attrs = append(attrs,
			slog.String("time_to_crack", s.TimeToCrack.Round(time.Millisecond).String()),
			slog.Int64("time_to_crack_ms", s.TimeToCrack.Milliseconds()),
		)
		if s.KeyRecovered {
			attrs = append(attrs, slog.Bool("key_recovered", true))
		}
		if len(s.CrackedPaths) > 0 {
			attrs = append(attrs, slog.Any("cracked_entries", s.CrackedPaths))
		}
		if includeSecrets && len(s.Passwords) > 0 {
			attrs = append(attrs, slog.Any("passwords", s.Passwords))
		}
	}
	attrs = append(attrs, extra...)

	lvl, msg := slog.LevelDebug, "file processed"
	if s.Cracked {
		lvl, msg = slog.LevelInfo, "file cracked"
	}
	l.LogAttrs(context.Background(), lvl, msg, attrs...)
}

// Sink returns an xcrack.Options.OnAudit callback that records every node the
// engine reports to l as a debug trace, so a library embedder who sets
// Options.OnAudit gets the same per-node execution trail the tools emit at
// --log-level debug. (The tools themselves use LogFile for the per-file headline
// record.) The recovered password rides along only when the engine was
// configured to include it (Options.AuditIncludeSecrets). Any extra attrs are
// attached to each record.
func Sink(l *slog.Logger, extra ...slog.Attr) func(xcrack.AuditEvent) {
	return func(ev xcrack.AuditEvent) { traceNode(l, ev, extra) }
}

// traceNode writes one per-node trace record at debug.
func traceNode(l *slog.Logger, ev xcrack.AuditEvent, extra []slog.Attr) {
	if l == nil {
		return
	}
	attrs := make([]slog.Attr, 0, 9+len(extra))
	attrs = append(attrs,
		slog.String("node", ev.Path),
		slog.String("type", ev.Format),
		slog.String("status", ev.Status),
		slog.Bool("encrypted", ev.Encrypted),
		slog.Int64("size", ev.Size),
	)
	if ev.Encrypted && ev.Status == "decrypted" {
		attrs = append(attrs,
			slog.String("time_to_crack", ev.TimeToCrack.Round(time.Millisecond).String()),
			slog.Int64("time_to_crack_ms", ev.TimeToCrack.Milliseconds()),
		)
		if ev.KeyRecovered {
			attrs = append(attrs, slog.Bool("key_recovered", true))
		}
		if ev.Password != "" {
			attrs = append(attrs, slog.String("password", ev.Password))
		}
	}
	attrs = append(attrs, extra...)
	l.LogAttrs(context.Background(), slog.LevelDebug, "node scanned", attrs...)
}
