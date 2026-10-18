package main

import (
	"time"

	"github.com/rom/xcrack/pkg/jobspec"
)

// fileConfig is the YAML config model. It is an alias of jobspec.Spec, the
// single canonical schema shared by the CLI's --config, the embeddable library
// and the xcrack-web advanced editor, so a capability expressible in the config
// is reachable from every surface. The CLI resolves flag/env/config precedence
// into these fields and then (where applicable) hands the result to the jobspec
// assembler.
type fileConfig = jobspec.Spec

// clusterServer is one xcrackd endpoint in the config's cluster block.
type clusterServer = jobspec.ClusterServer

// loadConfig reads and parses a YAML config file (leniently — unknown keys are
// ignored, preserving the CLI's long-standing behaviour).
func loadConfig(path string) (*fileConfig, error) {
	return jobspec.LoadFile(path)
}

func parseDuration(s string) (time.Duration, error) {
	if s == "" {
		return 0, nil
	}
	return time.ParseDuration(s)
}
