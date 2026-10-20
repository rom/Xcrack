package webui

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// This file is the transport-level hardening that wraps the whole mux: a CSRF
// guard on state-changing requests and a per-client rate limiter. Both are
// active regardless of whether the multi-user auth tier is on, because a
// localhost instance is still reachable by a malicious web page (DNS rebinding,
// localhost CSRF) and by a runaway client. Neither needs any change in the SPA:
// the CSRF guard reads headers the browser sets itself, and the rate limits sit
// well above interactive use.

// --- CSRF ------------------------------------------------------------------

// safeMethod reports whether a method is read-only (never state-changing), so
// the CSRF guard lets it through.
func safeMethod(m string) bool {
	switch m {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	}
	return false
}

// sameOriginOK decides whether a state-changing request is same-origin, using
// the headers a browser attaches automatically. It is deliberately strict only
// about what a browser sends: Sec-Fetch-Site (when present) must not be
// cross-site, and an Origin/Referer (when present) must match the request host.
// A non-browser client (curl, the CLI, a test) sends none of these and is
// allowed — CSRF is a browser-only attack, so there is nothing to forge.
func sameOriginOK(r *http.Request) bool {
	switch r.Header.Get("Sec-Fetch-Site") {
	case "same-origin", "same-site", "none":
		return true
	case "cross-site":
		return false
	}
	// Fall back to an Origin/Referer host comparison.
	if o := r.Header.Get("Origin"); o != "" {
		return originHost(o) == r.Host
	}
	if ref := r.Header.Get("Referer"); ref != "" {
		return originHost(ref) == r.Host
	}
	return true // no browser-origin signal at all: not a forgeable browser request
}

// originHost extracts the host[:port] from an Origin/Referer URL without a full
// URL parse (both are "scheme://host[:port][/...]").
func originHost(u string) string {
	if i := strings.Index(u, "://"); i >= 0 {
		u = u[i+3:]
	}
	if i := strings.IndexAny(u, "/?#"); i >= 0 {
		u = u[:i]
	}
	return u
}

// csrf rejects a cross-origin state-changing request before it reaches a
// handler. The OIDC redirect endpoints are exempt: /auth/callback is a top-level
// GET navigation carrying the provider's state parameter (its own CSRF token),
// not a same-origin fetch.
func (s *Server) csrf(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !safeMethod(r.Method) && !sameOriginOK(r) {
			writeErr(w, http.StatusForbidden, "cross-origin request refused (CSRF)")
			return
		}
		h.ServeHTTP(w, r)
	})
}

// --- rate limiting ---------------------------------------------------------

// rateLimiter is a fixed-window per-key counter. A zero limit disables it.
type rateLimiter struct {
	mu      sync.Mutex
	windows map[string]*rlWindow
	limit   int
	window  time.Duration
}

type rlWindow struct {
	count int
	reset time.Time
}

func newRateLimiter(limit int, window time.Duration) *rateLimiter {
	return &rateLimiter{windows: map[string]*rlWindow{}, limit: limit, window: window}
}

// allow records a hit for key and reports whether it is within the limit.
func (rl *rateLimiter) allow(key string) bool {
	if rl == nil || rl.limit <= 0 {
		return true
	}
	now := time.Now()
	rl.mu.Lock()
	defer rl.mu.Unlock()
	if len(rl.windows) > 16384 {
		for k, w := range rl.windows { // opportunistic sweep of expired windows
			if now.After(w.reset) {
				delete(rl.windows, k)
			}
		}
	}
	w := rl.windows[key]
	if w == nil || now.After(w.reset) {
		rl.windows[key] = &rlWindow{count: 1, reset: now.Add(rl.window)}
		return true
	}
	if w.count >= rl.limit {
		return false
	}
	w.count++
	return true
}

// clientIP returns the remote address's IP, honoring the first X-Forwarded-For
// hop only when the operator has declared the proxy trusted.
func clientIP(r *http.Request, trustProxy bool) string {
	if trustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			if i := strings.IndexByte(xff, ','); i >= 0 {
				xff = xff[:i]
			}
			if ip := strings.TrimSpace(xff); ip != "" {
				return ip
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// rateLimit wraps the mux so each client IP is bounded to a general request
// budget, with a stricter budget on the login endpoint (which triggers an
// outbound token exchange and is a brute-force target).
func (s *Server) rateLimit(h http.Handler) http.Handler {
	if s.limiter == nil && s.authLimiter == nil {
		return h
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := clientIP(r, s.cfg.TrustProxyHeaders)
		if r.URL.Path == "/auth/login" && !s.authLimiter.allow(ip) {
			writeErr(w, http.StatusTooManyRequests, "too many login attempts; slow down")
			return
		}
		if !s.limiter.allow(ip) {
			writeErr(w, http.StatusTooManyRequests, "rate limit exceeded; slow down")
			return
		}
		h.ServeHTTP(w, r)
	})
}
