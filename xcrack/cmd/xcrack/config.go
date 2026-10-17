package main

import (
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// fileConfig mirrors the YAML config file. Pointers are used where the zero
// value is meaningful, so "unset in config" is distinguishable from "set false".
type fileConfig struct {
	Concurrency struct {
		Workers   int `yaml:"workers"`
		FileJobs  int `yaml:"file_jobs"`
		MaxProcs  int `yaml:"max_procs"`
		BatchSize int `yaml:"batch_size"`
		Throttle  int `yaml:"throttle"`
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
	} `yaml:"search"`
	Candidates struct {
		Wordlists      []string `yaml:"wordlists"`
		Passwords      []string `yaml:"passwords"`
		Breach         []string `yaml:"breach"`           // frequency-annotated breach corpora
		BreachMinCount int64    `yaml:"breach_min_count"` // drop breach entries below this prevalence
		UseDefaultList *bool    `yaml:"use_default_list"`
		Swedish        bool     `yaml:"swedish"` // also try the built-in Swedish-targeted wordlist
	} `yaml:"candidates"`
	Patterns struct {
		Masks          []string          `yaml:"masks"`
		Rules          []string          `yaml:"rules"`
		CustomCharsets map[string]string `yaml:"custom_charsets"`
		HCMask         []string          `yaml:"hcmask"` // hashcat .hcmask files (per-line masks)
	} `yaml:"patterns"`
	Output struct {
		Format      string `yaml:"format"`
		ResultsFile string `yaml:"results_file"`
		LogLevel    string `yaml:"log_level"`
	} `yaml:"output"`
	Budget struct {
		PerFile string `yaml:"per_file"`
		Total   string `yaml:"total"`
	} `yaml:"budget"`
	Cluster struct {
		Servers       []clusterServer `yaml:"servers"`        // xcrackd endpoints to distribute across
		Mode          string          `yaml:"mode"`           // "collective" | "partition"
		Batch         int             `yaml:"batch"`          // candidates shipped per server request
		AllowDefaults bool            `yaml:"allow_defaults"` // let each server also use its own default list
		PerRequest    string          `yaml:"per_request"`    // per-request server deadline hint (e.g. 30s)
	} `yaml:"cluster"`
}

// clusterServer is one xcrackd endpoint in the config's cluster block.
type clusterServer struct {
	URL   string `yaml:"url"`
	Group string `yaml:"group"`
}

func loadConfig(path string) (*fileConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c fileConfig
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

func parseDuration(s string) (time.Duration, error) {
	if s == "" {
		return 0, nil
	}
	return time.ParseDuration(s)
}
