package webui

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/rom/xcrypto"
)

// Resume support closes two gaps against the CLI's long-run ergonomics:
//
//   - Challenge round-trip. The Tools tab can export a portable challenge
//     envelope to solve on an external cracker; decodeRecoveredPasswords brings
//     the solved result back in. A job's create form may carry one or more
//     `recovered` parts (a RecoveredPassword JSON object, or an array of them);
//     their passwords become the job's priority passwords, tried first on every
//     file — the GUI equivalent of the CLI's `--resume-from`.
//
//   - Checkpoint resume. A single-target crack persists its candidate position
//     under <job>/checkpoint so an interrupted run can pick up near where it
//     stopped. On re-run the old job's checkpoint is copied forward, so the
//     re-run resumes instead of restarting. The signature below ties a
//     checkpoint to its exact keyspace, so a changed spec or file starts fresh.

const checkpointSubdir = "checkpoint"

// decodeRecoveredPasswords parses a solved-challenge payload — a single
// xcrypto.RecoveredPassword object or a JSON array of them — and returns the
// non-empty passwords. It mirrors the CLI's loadRecoveredPasswords over bytes,
// rejecting an unknown envelope version.
func decodeRecoveredPasswords(data []byte) ([]string, error) {
	// An array first (export can emit several), else a single object.
	var arr []xcrypto.RecoveredPassword
	if err := json.Unmarshal(data, &arr); err == nil && len(arr) > 0 {
		var out []string
		for i := range arr {
			if arr[i].Version != xcrypto.RecoveredPasswordVersion {
				return nil, fmt.Errorf("unsupported recovered-password version %d", arr[i].Version)
			}
			if arr[i].Password != "" {
				out = append(out, arr[i].Password)
			}
		}
		return out, nil
	}
	rp, err := xcrypto.UnmarshalRecoveredPassword(data)
	if err != nil {
		return nil, err
	}
	if rp.Password == "" {
		return nil, nil
	}
	return []string{rp.Password}, nil
}

// specSig is a short, stable fingerprint of a job's spec YAML, used to key a
// checkpoint so a changed candidate configuration is never silently resumed.
func specSig(specYAML string) string {
	sum := sha256.Sum256([]byte(specYAML))
	return fmt.Sprintf("%x", sum[:8])
}

// checkpointSig ties a checkpoint file to one exact keyspace: the spec, the
// source file's name and its byte length. A mismatch (edited spec, different
// file) is treated by candidates.Checkpoint as a fresh start.
func checkpointSig(specSignature, name string, size int64) string {
	return fmt.Sprintf("%s:%s:%d", specSignature, name, size)
}

// checkpointPath is where a single-target crack persists its position for the
// given source file, under the job's checkpoint subdirectory.
func checkpointPath(jobDir, name string) string {
	return filepath.Join(jobDir, checkpointSubdir, safeSegment(name)+".ck")
}

// hasCheckpoint reports whether the job directory holds any persisted checkpoint
// (so an interrupted/canceled job can be resumed by re-running it).
func hasCheckpoint(jobDir string) bool {
	entries, err := os.ReadDir(filepath.Join(jobDir, checkpointSubdir))
	if err != nil {
		return false
	}
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".ck" {
			if info, err := e.Info(); err == nil && info.Size() > 0 {
				return true
			}
		}
	}
	return false
}

// copyCheckpoints copies every persisted checkpoint from one job directory to
// another, so a re-run resumes from the original's position. Missing source
// checkpoints are not an error (a fresh job simply starts from zero).
func copyCheckpoints(oldDir, newDir string) error {
	srcDir := filepath.Join(oldDir, checkpointSubdir)
	entries, err := os.ReadDir(srcDir)
	if err != nil {
		return nil // nothing to carry forward
	}
	dstDir := filepath.Join(newDir, checkpointSubdir)
	if err := os.MkdirAll(dstDir, 0o700); err != nil {
		return err
	}
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".ck" {
			continue
		}
		if err := copyFile(filepath.Join(srcDir, e.Name()), filepath.Join(dstDir, e.Name())); err != nil {
			return err
		}
	}
	return nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}
