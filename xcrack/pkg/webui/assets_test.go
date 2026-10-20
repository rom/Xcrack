package webui

import (
	"regexp"
	"strings"
	"testing"
)

// TestWizardControls guards the expanded attack wizard's controls and wiring:
// the markup must carry the preset chips, the attack-kind selector, the
// mangling (rule) and extra-source toggles, the wordlist picker and the
// feasibility-estimate host, and app.js must map them to the Crack form.
func TestWizardControls(t *testing.T) {
	html, err := staticFS.ReadFile("assets/index.html")
	if err != nil {
		t.Fatalf("read index.html: %v", err)
	}
	for _, id := range []string{
		`data-preset="personal"`, `data-preset="pin"`, `data-preset="passphrase"`,
		`id="wz-kind"`, `id="wz-cap"`, `id="wz-leet"`, `id="wz-digit"`, `id="wz-bang"`,
		`id="wz-years"`, `id="wz-wordlist"`, `id="wz-kw"`, `id="wz-prince"`, `id="wz-loopback"`,
		`id="wz-estimate"`,
	} {
		if !strings.Contains(string(html), id) {
			t.Errorf("index.html is missing wizard control %q", id)
		}
	}

	js, err := staticFS.ReadFile("assets/app.js")
	if err != nil {
		t.Fatalf("read app.js: %v", err)
	}
	for _, fn := range []string{"WZ_PRESETS", "wzApplyPreset", "wzUpdateEstimate", "wzRules", "wzPopulateWordlists", "buildFromWizard"} {
		if !strings.Contains(string(js), fn) {
			t.Errorf("app.js is missing wizard function/const %q", fn)
		}
	}
	// The build step must drive real Crack-form fields the engine consumes.
	for _, field := range []string{`$("rules")`, `$("hybrid_append")`, `$("spray_years")`, `$("lib_names")`, `$("masks")`} {
		if !strings.Contains(string(js), field) {
			t.Errorf("buildFromWizard no longer writes %s", field)
		}
	}
}

// TestJobProgressControls guards the job-progress UI: the "Ended" timestamp
// field, the results "X of Y decrypted" summary, and that the indeterminate
// progress bar stops animating once the event stream closes (keyed on
// evtSource), so a finished run doesn't sweep forever.
func TestJobProgressControls(t *testing.T) {
	html, err := staticFS.ReadFile("assets/index.html")
	if err != nil {
		t.Fatalf("read index.html: %v", err)
	}
	if !strings.Contains(string(html), `id="job-ended"`) {
		t.Error("index.html is missing the #job-ended timestamp field")
	}

	js, err := staticFS.ReadFile("assets/app.js")
	if err != nil {
		t.Fatalf("read app.js: %v", err)
	}
	js2 := string(js)
	if !strings.Contains(js2, `job-ended`) {
		t.Error("app.js never sets #job-ended")
	}
	if !strings.Contains(js2, "results-summary") || !strings.Contains(js2, "decrypted`") {
		t.Error("app.js is missing the 'X of Y decrypted' results summary")
	}
	// The indeterminate sweep must be gated on a live event stream so it stops
	// when the run ends.
	if !strings.Contains(js2, `bar.classList.toggle("indeterminate", evtSource != null)`) {
		t.Error("app.js no longer gates the indeterminate bar on evtSource; a finished run would animate forever")
	}
}

// TestAccessibilityMarkup guards the accessibility affordances: the ARIA tab
// pattern (tablist/tab/tabpanel), labelled dialogs, live regions, a labelled
// progressbar, and a skip link — plus the JS that keeps the tab + modal focus
// behaviour wired. A future edit that strips these should fail here.
func TestAccessibilityMarkup(t *testing.T) {
	html, err := staticFS.ReadFile("assets/index.html")
	if err != nil {
		t.Fatalf("read index.html: %v", err)
	}
	h := string(html)
	for _, want := range []string{
		`class="skip-link"`,            // skip to content
		`role="tablist"`, `role="tab"`, // tab semantics
		`role="tabpanel"`,                    // panel semantics
		`role="dialog"`, `aria-modal="true"`, // accessible dialogs
		`role="progressbar"`, `aria-valuemin="0"`, // labelled progress
		`role="status"`, `aria-live="polite"`, // live regions
		`id="main"`, // skip-link target
	} {
		if !strings.Contains(h, want) {
			t.Errorf("index.html is missing accessibility markup %q", want)
		}
	}
	// Every section's tab button must point at its panel (aria-controls) and
	// every panel must be labelled by its button (aria-labelledby).
	for _, tab := range []string{"crack", "history", "tools", "stats", "config"} {
		if !strings.Contains(h, `aria-controls="tab-`+tab+`"`) {
			t.Errorf("tab %q has no aria-controls to its panel", tab)
		}
	}

	js, err := staticFS.ReadFile("assets/app.js")
	if err != nil {
		t.Fatalf("read app.js: %v", err)
	}
	j := string(js)
	for _, fn := range []string{"openModal", "closeModal", "wireModalA11y", "setBarAria", "focusablesIn"} {
		if !strings.Contains(j, fn) {
			t.Errorf("app.js is missing accessibility helper %q", fn)
		}
	}
	// Tab activation must keep aria-selected in sync, and modals must trap focus.
	if !strings.Contains(j, "aria-selected") {
		t.Error("app.js no longer maintains aria-selected on the tabs")
	}
	if !strings.Contains(j, `document.activeElement === first`) {
		t.Error("app.js no longer traps Tab within the open dialog")
	}
}

// TestKeyAttackJobUI guards the "run as job" wiring for the long key attacks:
// the upload field and run button in the markup, and the JS that posts to the
// three new tool-job endpoints.
func TestKeyAttackJobUI(t *testing.T) {
	html, err := staticFS.ReadFile("assets/index.html")
	if err != nil {
		t.Fatalf("read index.html: %v", err)
	}
	for _, want := range []string{`id="cli-upload"`, `id="cli-run"`} {
		if !strings.Contains(string(html), want) {
			t.Errorf("index.html is missing key-attack job control %q", want)
		}
	}
	js, err := staticFS.ReadFile("assets/app.js")
	if err != nil {
		t.Fatalf("read app.js: %v", err)
	}
	for _, want := range []string{"runCLIAsJob", "/tools/thunder-gen", "/tools/pdf-keyattack", "/tools/office-keyattack"} {
		if !strings.Contains(string(js), want) {
			t.Errorf("app.js is missing key-attack job wiring %q", want)
		}
	}
}

// TestResumeUI guards the resume affordances in the SPA: the solved-challenge
// upload field on the Crack form and the JS that posts it as a `recovered` part,
// so the challenge round-trip stays wired end to end.
func TestResumeUI(t *testing.T) {
	html, err := staticFS.ReadFile("assets/index.html")
	if err != nil {
		t.Fatalf("read index.html: %v", err)
	}
	if !strings.Contains(string(html), `id="recovered"`) {
		t.Error("index.html is missing the #recovered solved-challenge upload field")
	}
	js, err := staticFS.ReadFile("assets/app.js")
	if err != nil {
		t.Fatalf("read app.js: %v", err)
	}
	if !strings.Contains(string(js), `fd.append("recovered"`) {
		t.Error("app.js no longer posts the solved-challenge file as a `recovered` part")
	}
	if !strings.Contains(string(js), "j.resumable") {
		t.Error("app.js no longer surfaces a resumable job's resume button")
	}
}

// TestI18nFramework guards the internationalisation wiring: the page must load
// i18n.js and carry a language selector, and every data-i18n* key the markup
// references must be defined in BOTH shipped catalogues (English and Swedish),
// so a newly instrumented node can never ship with a missing translation key.
func TestI18nFramework(t *testing.T) {
	html, err := staticFS.ReadFile("assets/index.html")
	if err != nil {
		t.Fatalf("read index.html: %v", err)
	}
	h := string(html)
	for _, want := range []string{`src="i18n.js"`, `id="lang"`, `value="sv"`, `data-i18n=`} {
		if !strings.Contains(h, want) {
			t.Errorf("index.html is missing i18n wiring %q", want)
		}
	}

	js, err := staticFS.ReadFile("assets/i18n.js")
	if err != nil {
		t.Fatalf("read i18n.js: %v", err)
	}
	j := string(js)
	for _, want := range []string{"window.XI18N", "function t(", "setLocale", "en:", "sv:"} {
		if !strings.Contains(j, want) {
			t.Errorf("i18n.js is missing %q", want)
		}
	}

	// Every key referenced in the markup must be defined in both catalogues.
	// Each catalogue carries the key once, so `"key":` must appear twice.
	keyRe := regexp.MustCompile(`data-i18n(?:-[a-z]+)?="([^"]+)"`)
	seen := map[string]bool{}
	for _, m := range keyRe.FindAllStringSubmatch(h, -1) {
		key := m[1]
		if seen[key] {
			continue
		}
		seen[key] = true
		if n := strings.Count(j, `"`+key+`":`); n < 2 {
			t.Errorf("i18n key %q is referenced in the markup but defined %d time(s) in i18n.js (want it in both en and sv)", key, n)
		}
	}
	if len(seen) == 0 {
		t.Error("no data-i18n keys found in index.html")
	}

	// app.js must initialise i18n and wire the selector.
	appjs, err := staticFS.ReadFile("assets/app.js")
	if err != nil {
		t.Fatalf("read app.js: %v", err)
	}
	for _, want := range []string{"XI18N.init()", "wireLang"} {
		if !strings.Contains(string(appjs), want) {
			t.Errorf("app.js is missing i18n wiring %q", want)
		}
	}
}

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
