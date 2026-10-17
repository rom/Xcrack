//go:build !windows && !plan9 && !js && !wasip1

package auditlog

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"log/syslog"
	"strings"
	"sync"
)

// newSyslogHandler dials the system logger and returns a slog.Handler that
// routes each record to the matching syslog severity (Debug/Info/Warning/Err).
// With an empty network and address it connects to the local syslog socket;
// otherwise it dials the named remote ("udp"/"tcp", host:port).
func newSyslogHandler(cfg Config, lvl slog.Leveler) (slog.Handler, io.Closer, error) {
	tag := cfg.SyslogTag
	if tag == "" {
		tag = defaultTag()
	}
	// LOG_USER keeps these tool/daemon messages out of the kernel/auth facilities;
	// the per-call severity (set below) is what actually classifies each line.
	w, err := syslog.Dial(cfg.SyslogNetwork, cfg.SyslogAddress, syslog.LOG_INFO|syslog.LOG_USER, tag)
	if err != nil {
		return nil, nil, fmt.Errorf("connect to syslog: %w", err)
	}
	buf := &bytes.Buffer{}
	// syslog stamps its own time and host, so drop slog's timestamp from the
	// payload to avoid a duplicate.
	opts := &slog.HandlerOptions{Level: lvl, ReplaceAttr: dropTime}
	return &syslogHandler{
		w:     w,
		mu:    &sync.Mutex{},
		buf:   buf,
		inner: newHandler(buf, cfg.Format, opts),
	}, w, nil
}

func dropTime(groups []string, a slog.Attr) slog.Attr {
	if len(groups) == 0 && a.Key == slog.TimeKey {
		return slog.Attr{}
	}
	return a
}

// syslogHandler formats each record with an inner text/JSON handler (into a
// shared, mutex-guarded buffer) and forwards the result to syslog at the
// severity matching the record's level. WithAttrs/WithGroup share the buffer and
// mutex so concurrent emitters stay serialized and correctly formatted.
type syslogHandler struct {
	w     *syslog.Writer
	mu    *sync.Mutex
	buf   *bytes.Buffer
	inner slog.Handler
}

func (h *syslogHandler) Enabled(ctx context.Context, lvl slog.Level) bool {
	return h.inner.Enabled(ctx, lvl)
}

func (h *syslogHandler) Handle(ctx context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.buf.Reset()
	if err := h.inner.Handle(ctx, r); err != nil {
		return err
	}
	msg := strings.TrimRight(h.buf.String(), "\n")
	switch {
	case r.Level >= slog.LevelError:
		return h.w.Err(msg)
	case r.Level >= slog.LevelWarn:
		return h.w.Warning(msg)
	case r.Level >= slog.LevelInfo:
		return h.w.Info(msg)
	default:
		return h.w.Debug(msg)
	}
}

func (h *syslogHandler) WithAttrs(as []slog.Attr) slog.Handler {
	return &syslogHandler{w: h.w, mu: h.mu, buf: h.buf, inner: h.inner.WithAttrs(as)}
}

func (h *syslogHandler) WithGroup(name string) slog.Handler {
	return &syslogHandler{w: h.w, mu: h.mu, buf: h.buf, inner: h.inner.WithGroup(name)}
}
