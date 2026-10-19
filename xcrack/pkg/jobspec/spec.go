// Package jobspec is the single, reusable description of a recovery job: the
// YAML configuration model the xcrack CLI's --config consumes and the xcrack-web
// advanced editor edits, together with the logic that turns that model into the
// engine's xcrack.Options and the per-file candidate sources.
//
// It exists so every delivery surface — the CLI, the embeddable library, and the
// web GUI — assembles the engine from one place. A capability expressible in the
// YAML is therefore reachable everywhere, with no per-surface duplication of the
// candidate-pipeline wiring. The CLI's --config type is an alias of Spec, so the
// schema the web editor edits is byte-for-byte the schema the CLI already loads.
//
// A Spec is a fully-resolved job description: unlike the CLI's flag parsing it
// carries no notion of precedence (flags > env > config > defaults). The CLI
// resolves those into field values and the web UI sets them directly; either way
// NewAssembler and BuildOptions interpret the resulting Spec the same way.
package jobspec

import (
	"bytes"
	"fmt"
	"io"
	"os"

	"gopkg.in/yaml.v3"
)

// Spec mirrors the YAML config file. Pointers are used where the zero value is
// meaningful, so "unset" is distinguishable from "set false" (the CLI relies on
// this to let a config toggle be overridden by a flag).
//
// The blocks up to and including Cluster are the long-standing CLI config
// schema; the fields tagged "(web/library)" below extend it to cover options
// that used to be reachable only as CLI flags, so the full feature surface is
// expressible in one document.
type Spec struct {
	Concurrency struct {
		Workers      int  `yaml:"workers"`
		FileJobs     int  `yaml:"file_jobs"`
		MaxProcs     int  `yaml:"max_procs"`
		BatchSize    int  `yaml:"batch_size"`
		Throttle     int  `yaml:"throttle"`
		DualPipeline bool `yaml:"dual_pipeline"` // race the CPU search and the --gpu sweep over one shared keyspace per file
		GPU          bool `yaml:"gpu"`           // (web/library) offload the shared PBKDF2 sweep to an OpenCL device (needs a -tags opencl build on GPU hardware; pure-Go falls back to the CPU)
	} `yaml:"concurrency"`
	Limits struct {
		MaxDepth      int   `yaml:"max_depth"`
		MaxTotalBytes int64 `yaml:"max_total_bytes"`
		MaxNodes      int   `yaml:"max_nodes"`
		MaxEntrySize  int64 `yaml:"max_entry_size"`
		MaxRatio      int   `yaml:"max_ratio"`
		MaxCandidates int64 `yaml:"max_candidates"`
	} `yaml:"limits"`
	Recursion struct {
		Recurse          *bool `yaml:"recurse"`
		ExplodeDocuments bool  `yaml:"explode_documents"`
	} `yaml:"recursion"`
	Search struct {
		Promote       *bool    `yaml:"promote_passwords"`
		Context       bool     `yaml:"context_candidates"`
		Hint          bool     `yaml:"hint_candidates"`
		HintRules     []string `yaml:"hint_rules"`     // hashcat-style rule lines applied to hint-derived words
		HybridAppend  []string `yaml:"hybrid_append"`  // masks appended to each wordlist word (dict+mask)
		HybridPrepend []string `yaml:"hybrid_prepend"` // masks prepended to each wordlist word (mask+dict)
		ToggleCase    bool     `yaml:"toggle_case"`    // case-toggle variants of each wordlist word
		Prince        bool     `yaml:"prince"`         // PRINCE chains over the wordlists
		KeyboardWalk  bool     `yaml:"keyboard_walk"`  // QWERTY keyboard-adjacency walks
		Spray         bool     `yaml:"spray"`          // curated password-spraying set
		SprayTokens   []string `yaml:"spray_tokens"`   // org/product/user tokens mangled into the spray set
		Adaptive      bool     `yaml:"adaptive"`       // corpus-wide adaptive promotion across files
		Shard         string   `yaml:"shard"`          // distributed cracking: this worker's shard, "I/N"
		Markov        bool     `yaml:"markov"`         // Markov best-first generated guesses
		Order         string   `yaml:"order"`          // reorder wordlist candidates: "markov" | "none"
		CostQueue     bool     `yaml:"cost_queue"`     // triage many files weakest/fastest-attack-first

		// The fields below used to be reachable only as CLI flags.
		Loopback        bool     `yaml:"loopback"`         // (web/library) feed cached/pot recovered passwords back through the rules
		PCFG            bool     `yaml:"pcfg"`             // (web/library) train a PCFG on the candidate words and generate guesses in probability order
		PCFGMax         int      `yaml:"pcfg_max"`         // (web/library) max PCFG guesses (0 => 100000)
		MarkovMax       int      `yaml:"markov_max"`       // (web/library) max Markov guesses (0 => 1,000,000)
		MarkovThreshold int      `yaml:"markov_threshold"` // (web/library) cap --markov to the N likeliest next chars per position (0 => 15)
		MarkovPos       bool     `yaml:"markov_pos"`       // (web/library) use a position-aware (2D) Markov model
		OrderMax        int      `yaml:"order_max"`        // (web/library) max wordlist entries to buffer and reorder (0 => 1,000,000)
		Increment       string   `yaml:"increment"`        // (web/library) expand each mask over MIN:MAX tokens, shortest first
		SprayYears      []int    `yaml:"spray_years"`      // (web/library) years used in spray patterns (default current/previous)
		Combinator      struct { // (web/library) combinator attack: every left word + every right word
			Left  string `yaml:"left"`
			Right string `yaml:"right"`
			Sep   string `yaml:"sep"`
		} `yaml:"combinator"`
	} `yaml:"search"`
	Candidates struct {
		Wordlists      []string `yaml:"wordlists"`
		Passwords      []string `yaml:"passwords"`
		Breach         []string `yaml:"breach"`           // frequency-annotated breach corpora
		BreachMinCount int64    `yaml:"breach_min_count"` // drop breach entries below this prevalence
		UseDefaultList *bool    `yaml:"use_default_list"`
		Swedish        bool     `yaml:"swedish"` // also try the built-in Swedish-targeted wordlist

		// The fields below used to be reachable only as CLI flags.
		MinLength     int      `yaml:"min_length"`     // (web/library) skip candidates shorter than N characters (0 => no minimum)
		MaxLength     int      `yaml:"max_length"`     // (web/library) skip candidates longer than N characters (0 => no maximum)
		Encoding      string   `yaml:"encoding"`       // (web/library) transcode each candidate before testing: utf-8|latin1|utf-16le|utf-16be
		PasswordFiles []string `yaml:"password_files"` // (web/library) files of candidate passwords (one per line), tried first
	} `yaml:"candidates"`
	Patterns struct {
		Masks          []string          `yaml:"masks"`
		Rules          []string          `yaml:"rules"`
		CustomCharsets map[string]string `yaml:"custom_charsets"`
		HCMask         []string          `yaml:"hcmask"` // hashcat .hcmask files (per-line masks)

		// The fields below used to be reachable only as CLI flags.
		GenerateRules     int   `yaml:"generate_rules"`      // (web/library) generate N random mangling rules and add them to the pool
		GenerateRulesSeed int64 `yaml:"generate_rules_seed"` // (web/library) seed for generate_rules (same seed => same rules)
	} `yaml:"patterns"`
	Input struct {
		As string `yaml:"as"` // (web/library) force a scheme for a magic-less file (e.g. "sqlcipher")
	} `yaml:"input"`
	Output struct {
		Format        string `yaml:"format"`
		ResultsFile   string `yaml:"results_file"`
		LogLevel      string `yaml:"log_level"`
		LogFormat     string `yaml:"log_format"`         // "text" (default) or "json"
		LogFile       string `yaml:"log_file"`           // append structured log/audit lines to this path
		Syslog        bool   `yaml:"syslog"`             // send log/audit lines to the system logger
		SyslogAddress string `yaml:"syslog_address"`     // remote syslog host:port ("" = local socket)
		SyslogNetwork string `yaml:"syslog_network"`     // "udp"/"tcp" for a remote syslog ("" = local socket)
		SyslogTag     string `yaml:"syslog_tag"`         // syslog tag/ident (default: program name)
		AuditPassword bool   `yaml:"audit_log_password"` // include the recovered password in the audit log
		ExtractSuffix string `yaml:"extract_suffix"`     // suffix for each source's extracted-tree dir under --out (default ".extracted")
		// CacheEncryption controls at-rest protection of the found-password
		// cache/potfile: "" / "none" (plaintext) or "tpm" (the cache key is sealed
		// to this host's TPM; requires a -tags tpm build). (web/library)
		CacheEncryption string `yaml:"cache_encryption"`
	} `yaml:"output"`
	Budget struct {
		PerFile string `yaml:"per_file"`
		Total   string `yaml:"total"`
	} `yaml:"budget"`
	Cluster struct {
		Servers       []ClusterServer `yaml:"servers"`        // xcrackd endpoints to distribute across
		Mode          string          `yaml:"mode"`           // "collective" | "partition"
		Batch         int             `yaml:"batch"`          // candidates shipped per server request
		AllowDefaults bool            `yaml:"allow_defaults"` // let each server also use its own default list
		PerRequest    string          `yaml:"per_request"`    // per-request server deadline hint (e.g. 30s)
		TLS           struct {
			CA         string `yaml:"ca"`          // PEM CA bundle to verify the server cert (private CA / self-signed)
			Cert       string `yaml:"cert"`        // client certificate (PEM) for mutual TLS
			Key        string `yaml:"key"`         // private key (PEM) for cert
			ServerName string `yaml:"server_name"` // expected server cert name (SNI / verification override)
			Insecure   bool   `yaml:"insecure"`    // skip server verification (INSECURE — testing only)
		} `yaml:"tls"`
	} `yaml:"cluster"`
}

// ClusterServer is one xcrackd endpoint in the config's cluster block.
type ClusterServer struct {
	URL   string `yaml:"url"`
	Group string `yaml:"group"`
}

// LoadFile reads and parses a YAML spec from path, leniently (unknown keys are
// ignored). This matches the CLI's long-standing --config behaviour, so an
// existing config keeps loading unchanged.
func LoadFile(path string) (*Spec, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(data)
}

// Parse decodes a YAML spec from bytes, leniently: unknown keys are ignored, so
// a spec written for a newer schema still loads on an older binary.
func Parse(data []byte) (*Spec, error) {
	var s Spec
	if err := yaml.Unmarshal(data, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// ParseStrict is Parse with unknown-field rejection, so a typo in a key (e.g.
// "wordlist" for "wordlists") fails loudly rather than being silently ignored.
// The web UI uses it to validate an edited document before queuing a job; the
// CLI stays lenient via Parse for backwards compatibility.
func ParseStrict(data []byte) (*Spec, error) {
	var s Spec
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&s); err != nil {
		// An empty document decodes to EOF; that is a valid "all defaults" job.
		if err == io.EOF {
			return &Spec{}, nil
		}
		return nil, err
	}
	return &s, nil
}

// Marshal renders the spec back to YAML (used by the web UI to serialize an
// edited job, and to seed the advanced-mode editor from the easy-mode form).
func (s *Spec) Marshal() ([]byte, error) { return yaml.Marshal(s) }

// recurse reports whether container decomposition is enabled (default true).
func (s *Spec) recurse() bool { return s.Recursion.Recurse == nil || *s.Recursion.Recurse }

// promote reports whether password promotion is enabled (default true).
func (s *Spec) promote() bool { return s.Search.Promote == nil || *s.Search.Promote }

// useDefaultList reports whether the built-in common-password list is enabled
// (default true).
func (s *Spec) useDefaultList() bool {
	return s.Candidates.UseDefaultList == nil || *s.Candidates.UseDefaultList
}

// Validate checks the spec for internal consistency without touching the
// filesystem or building anything, so the web UI can reject a bad document
// before a job is queued. It returns the first problem found.
func (s *Spec) Validate() error {
	if _, _, err := parseShard(s.Search.Shard); err != nil {
		return fmt.Errorf("search.shard: %w", err)
	}
	if _, _, err := parseIncrement(s.Search.Increment); err != nil {
		return fmt.Errorf("search.increment: %w", err)
	}
	if (s.Search.Combinator.Left == "") != (s.Search.Combinator.Right == "") {
		return fmt.Errorf("search.combinator: left and right must be given together")
	}
	switch s.Search.Order {
	case "", "none", "markov":
	default:
		return fmt.Errorf("search.order: unknown mode %q (supported: markov, none)", s.Search.Order)
	}
	if s.Candidates.Encoding != "" {
		if _, err := parseEncodingName(s.Candidates.Encoding); err != nil {
			return fmt.Errorf("candidates.encoding: %w", err)
		}
	}
	if s.Input.As != "" {
		if _, ok := forceRegistry(s.Input.As); !ok {
			return fmt.Errorf("input.as: unknown force-format %q (supported: sqlcipher, vba)", s.Input.As)
		}
	}
	switch s.Output.Format {
	case "", "text", "json", "jsonl":
	default:
		return fmt.Errorf("output.format: unknown format %q (supported: text, json, jsonl)", s.Output.Format)
	}
	if s.Budget.PerFile != "" {
		if _, err := parseDuration(s.Budget.PerFile); err != nil {
			return fmt.Errorf("budget.per_file: %w", err)
		}
	}
	if s.Budget.Total != "" {
		if _, err := parseDuration(s.Budget.Total); err != nil {
			return fmt.Errorf("budget.total: %w", err)
		}
	}
	return nil
}
