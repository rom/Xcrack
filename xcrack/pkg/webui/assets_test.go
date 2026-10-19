package webui

import (
	"strings"
	"testing"
)

// TestLoginGateHiddenGuard guards against a regression where the full-screen
// login overlay (`.login-gate`) is styled `display:flex` but has no
// `[hidden]` rule, so the `hidden` attribute (and the `hidden=true` the SPA
// sets in single-user mode / once signed in) is overridden and the gate covers
// the app anyway — showing a "sign in" prompt whose button hits /auth/login and
// 503s with "authentication is not configured". The gate must disappear when
// hidden, in the CSS and by default in the markup.
func TestLoginGateHiddenGuard(t *testing.T) {
	css, err := staticFS.ReadFile("assets/style.css")
	if err != nil {
		t.Fatalf("read style.css: %v", err)
	}
	if !strings.Contains(string(css), ".login-gate[hidden]") {
		t.Error("style.css must define a `.login-gate[hidden]` rule so the hidden attribute wins over display:flex")
	}

	html, err := staticFS.ReadFile("assets/index.html")
	if err != nil {
		t.Fatalf("read index.html: %v", err)
	}
	// The gate must carry the `hidden` attribute by default so it does not flash
	// before applyAuthGate() runs (and stays hidden in single-user mode).
	gate := `id="login-gate"`
	i := strings.Index(string(html), gate)
	if i < 0 {
		t.Fatalf("index.html has no %s element", gate)
	}
	// Look at the opening tag that carries the id.
	tagStart := strings.LastIndex(string(html[:i]), "<")
	tagEnd := strings.Index(string(html[i:]), ">")
	if tagStart < 0 || tagEnd < 0 {
		t.Fatal("could not isolate the #login-gate opening tag")
	}
	tag := string(html[tagStart : i+tagEnd+1])
	if !strings.Contains(tag, "hidden") {
		t.Errorf("the #login-gate element must have the `hidden` attribute by default; tag was %q", tag)
	}
}
