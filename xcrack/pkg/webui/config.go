package webui

import (
	"log/slog"

	"github.com/rom/xcrack/pkg/jobspec"
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
