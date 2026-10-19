package webui

import (
	"sort"

	"github.com/rom/xcrack/pkg/xcrack"
)

// Meta is the UI bootstrap payload: server capabilities, the supported formats,
// and a commented starter spec for the editor.
type Meta struct {
	Version       string       `json:"version"`
	GPUAvailable  bool         `json:"gpu_available"`
	TPMBuild      bool         `json:"tpm_build"`
	ExposeSecrets bool         `json:"expose_secrets"`
	TLS           bool         `json:"tls"`          // served over HTTPS
	AuthEnabled   bool         `json:"auth_enabled"` // multi-user OIDC on
	Formats       []FormatInfo `json:"formats"`
	StarterSpec   string       `json:"starter_spec"`
}

// FormatInfo describes one supported format for the UI.
type FormatInfo struct {
	Name       string `json:"name"`
	Container  bool   `json:"container"`
	Encrypted  bool   `json:"encrypted"`
	Explodable bool   `json:"explodable"`
}

// buildMeta assembles the bootstrap payload once per request (cheap).
func buildMeta(cfg Config) Meta {
	var formats []FormatInfo
	for _, f := range xcrack.DefaultRegistry().Formats() {
		c := f.Caps()
		formats = append(formats, FormatInfo{
			Name:       f.Name(),
			Container:  c.Container,
			Encrypted:  c.Encrypted,
			Explodable: c.Explodable,
		})
	}
	sort.Slice(formats, func(i, j int) bool { return formats[i].Name < formats[j].Name })
	return Meta{
		Version:       cfg.Version,
		GPUAvailable:  cfg.GPUAvailable,
		TPMBuild:      cfg.TPMBuild,
		ExposeSecrets: cfg.ExposeSecrets,
		TLS:           cfg.TLS,
		AuthEnabled:   cfg.Auth.Enabled,
		Formats:       formats,
		StarterSpec:   starterSpec,
	}
}

// starterSpec is a commented, ready-to-edit job spec for the advanced editor. It
// shows the most common knobs with safe defaults; every other field documented
// in config/README is also accepted.
const starterSpec = `# Xcrack job configuration — edit, then Validate and Run.
# Every key is optional; omitted keys use the engine defaults.

candidates:
  use_default_list: true      # the built-in common-password list
  # wordlists: [rockyou.txt]  # upload wordlists, then name them here
  # passwords: [hunter2]      # explicit guesses, tried first
  # min_length: 1
  # max_length: 0             # 0 = no maximum

patterns:
  # masks: ["?d?d?d?d"]       # brute-force keyspaces (?l ?u ?d ?s ?a)
  # rules: ["c", "$1", "$2$0$2$3"]

search:
  # context_candidates: true  # guess from file names + plain siblings
  # hint_candidates: true     # use an embedded password hint
  # markov: true              # statistical best-first generation
  # prince: true
  # toggle_case: true

concurrency:
  # workers: 0                # 0 = one per CPU
  # gpu: false                # needs a -tags opencl build on GPU hardware

limits:
  # max_candidates: 0         # 0 = unlimited

budget:
  # per_file: 30s             # give up on a file after this long
  # total: 10m
`
