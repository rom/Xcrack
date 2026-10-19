package webui

import (
	"log/slog"

	"github.com/rom/xcrack/pkg/jobspec"
	"github.com/rom/xcrack/pkg/securecache"
	"github.com/rom/xcrack/pkg/xcrack"
)

// Config tunes the web backend. The zero value is usable; NewServer/NewManager
// apply defaults for any unset field.
type Config struct {
	// WorkDir is the root for per-job working directories (uploads, auxiliary
	// wordlists, extracted output). Default: <os-temp>/xcrack-web.
	WorkDir string
	// DocsDir is a directory of Markdown docs served in the in-app documentation
	// browser. Empty disables it beyond the built-in quick-start page.
	DocsDir string
	// MaxUploadBytes bounds a single job-submission request body. Default 512 MiB.
	MaxUploadBytes int64
	// MaxConcurrentJobs caps how many jobs run at once; jobs beyond the cap stay
	// queued until a slot frees. 0 (default) means unlimited.
	MaxConcurrentJobs int
	// ExposeSecrets lets recovered passwords appear in the API responses and the
	// live event stream. The web UI is the user's own recovery console, so a
	// localhost instance wants this on; a shared/public instance may turn it off
	// so the trail (and anyone watching) stays secrets-free.
	ExposeSecrets bool
	// AllowServerPaths lets a submitted spec reference arbitrary server-side file
	// paths (wordlists, breach corpora, …) instead of only files uploaded with
	// the job. It is OFF by default: a remote client can reach only what it
	// uploads. Enable it only for a trusted, local single-user instance.
	AllowServerPaths bool
	// Accelerator, if set, is consulted when a job requests the GPU tier
	// (spec.concurrency.gpu). It returns the accelerator, a closer, and ok=false
	// when no device is usable (the run then falls back to the CPU). The binary
	// provides it so the webui package stays free of the OpenCL build tag.
	Accelerator func(spec *jobspec.Spec, log *slog.Logger) (xcrack.Accelerator, func(), bool)
	// GPUAvailable reports (for the UI) whether this build can use a GPU tier.
	GPUAvailable bool
	// TPMBuild reports (for the UI) whether this build includes the TPM-sealed
	// found-password cache.
	TPMBuild bool
	// Version is reported to the UI.
	Version string
	// Auth enables multi-user access via OIDC. Its zero value keeps the
	// single-user console (no login, no per-user ownership) unchanged.
	Auth AuthConfig
	// Sealer, if set, seals the found-password vault (potfile) at rest — the
	// binary provides a TPM sealer so the webui package stays free of the TPM
	// build tag. Nil keeps a plaintext vault.
	Sealer securecache.Sealer
}

// AuthConfig turns the console into a multi-user application fronted by an OIDC
// identity provider. When Enabled is false (the default) there is no login and
// every request is the implicit local owner — a localhost instance is unchanged.
type AuthConfig struct {
	// Enabled turns on login + per-user job ownership.
	Enabled bool
	// Issuer is the OIDC issuer URL (its /.well-known/openid-configuration is
	// fetched at startup). Required when Enabled.
	Issuer string
	// ClientID / ClientSecret identify this app to the provider.
	ClientID     string
	ClientSecret string
	// RedirectURL is this server's own /auth/callback URL, registered with the
	// provider (e.g. https://host:8443/auth/callback).
	RedirectURL string
	// Scopes requested at login; defaults to openid, email, profile.
	Scopes []string
	// Admins lists subjects or email addresses allowed to see and manage every
	// user's jobs (not just their own).
	Admins []string
	// CookieSecure sets the Secure flag on the session cookie. Default true; set
	// false only for plain-HTTP local testing.
	CookieSecure bool
}

// applyDefaults fills unset fields with their defaults. It is idempotent and
// called by both NewServer and NewManager so the Server and Manager share one
// fully-resolved config.
func (c *Config) applyDefaults() {
	if c.WorkDir == "" {
		c.WorkDir = defaultWorkDir()
	}
	if c.MaxUploadBytes <= 0 {
		c.MaxUploadBytes = 512 << 20
	}
}
