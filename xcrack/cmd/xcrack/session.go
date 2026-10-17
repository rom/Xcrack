package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
)

// session persists which files of a multi-file batch have been fully searched,
// so an interrupted run resumed with the same --session skips the files it
// already finished (found or exhausted) and continues with the rest. It is the
// batch-level complement to --checkpoint (which resumes the candidate position
// within a single file). A file is recorded only once its search ran to
// completion, so a file in flight when the run was killed is retried.
type session struct {
	path string
	mu   sync.Mutex
	st   sessionData
}

type sessionData struct {
	Sig  string              `json:"sig"`  // candidate-config signature; a change starts fresh
	Done map[string][]string `json:"done"` // file path -> recovered passwords (empty = searched, none found)
}

// loadSession reads an existing session file if its signature matches sig,
// otherwise starts a fresh session (warning if a stale one was present).
func loadSession(path, sig string) *session {
	s := &session{path: path, st: sessionData{Sig: sig, Done: map[string][]string{}}}
	data, err := os.ReadFile(path)
	if err != nil {
		return s
	}
	var prev sessionData
	if json.Unmarshal(data, &prev) == nil && prev.Sig == sig && prev.Done != nil {
		s.st.Done = prev.Done
	} else {
		fmt.Fprintf(os.Stderr, "xcrack: --session %s: candidate set changed (or file unreadable); starting a fresh session\n", path)
	}
	return s
}

// get returns a file's recorded recovered passwords and whether it is done.
func (s *session) get(path string) ([]string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	pw, ok := s.st.Done[path]
	return pw, ok
}

// markDone records that a file was fully searched, with any recovered passwords,
// and persists the session immediately so an interrupt loses nothing already done.
func (s *session) markDone(path string, pw []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.st.Done == nil {
		s.st.Done = map[string][]string{}
	}
	s.st.Done[path] = append([]string(nil), pw...)
	s.persistLocked()
}

func (s *session) persistLocked() {
	data, err := json.MarshalIndent(s.st, "", "  ")
	if err != nil {
		return
	}
	tmp := s.path + ".tmp"
	if os.WriteFile(tmp, data, 0o600) == nil {
		_ = os.Rename(tmp, s.path) // atomic replace
	}
}
