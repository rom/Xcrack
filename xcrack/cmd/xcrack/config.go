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
		Promote *bool `yaml:"promote_passwords"`
		Context bool  `yaml:"context_candidates"`
	} `yaml:"search"`
	Candidates struct {
		Wordlists      []string `yaml:"wordlists"`
		Passwords      []string `yaml:"passwords"`
		UseDefaultList *bool    `yaml:"use_default_list"`
	} `yaml:"candidates"`
	Patterns struct {
		Masks          []string          `yaml:"masks"`
		Rules          []string          `yaml:"rules"`
		CustomCharsets map[string]string `yaml:"custom_charsets"`
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
