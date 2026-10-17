//go:build windows || plan9 || js || wasip1

package auditlog

import (
	"errors"
	"io"
	"log/slog"
)

// ErrSyslogUnsupported is returned by New when --syslog is requested on a
// platform without a system logger (Windows, Plan 9, js/wasm).
var ErrSyslogUnsupported = errors.New("syslog logging is not supported on this platform")

func newSyslogHandler(cfg Config, lvl slog.Leveler) (slog.Handler, io.Closer, error) {
	return nil, nil, ErrSyslogUnsupported
}
