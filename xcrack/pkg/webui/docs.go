package webui

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// DocEntry names one in-app documentation page.
type DocEntry struct {
	Name  string `json:"name"`  // request id, e.g. "USERMANUAL.md" or "quickstart"
	Title string `json:"title"` // display title
}

// builtinQuickstart is always available, even without a DocsDir, so the
// documentation tab is never empty.
const builtinQuickstartName = "quickstart"

const builtinQuickstart = `# Xcrack — Quick start

Xcrack recovers access to password-protected and encrypted files. This web
console drives the same engine as the ` + "`xcrack`" + ` command-line tool.

## Recover a file

1. Go to **Crack**.
2. **Drop or choose** the locked file(s) to recover.
3. (Optional) Add a **wordlist** and turn on generators such as **masks**,
   **rules**, **Markov** or **PRINCE** under the candidate sources.
4. Press **Run**. Progress, the live log and any recovered passwords appear as
   the search proceeds.
5. When a file is unlocked you can **download** its decrypted contents.

## Easy vs. advanced mode

- **Easy mode** is a guided form covering the common options.
- **Advanced mode** adds every engine knob and an **IDE-style editor** for the
  job's YAML configuration — the exact same schema the ` + "`xcrack --config`" + `
  CLI flag accepts. Use **Validate** to check it and **Format** to tidy it.

## Statistics

The **Statistics** tab charts candidates tried, throughput, and the
decrypted/locked breakdown for the current run, plus the aggregate engine
counters.

## Documentation

The full user manual and reference are available under the **Docs** tab when the
server is started with a documentation directory (see ` + "`--docs-dir`" + `).

> Authorized use only: operate on files you own or are permitted to access.
`

// listDocs returns the available documentation pages: the built-in quick-start
// plus every Markdown file in DocsDir (if configured).
func (m *Manager) listDocs() []DocEntry {
	out := []DocEntry{{Name: builtinQuickstartName, Title: "Quick start"}}
	dir := m.cfg.DocsDir
	if dir == "" {
		return out
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return out
	}
	var docs []DocEntry
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(strings.ToLower(e.Name()), ".md") {
			continue
		}
		docs = append(docs, DocEntry{Name: e.Name(), Title: docTitle(filepath.Join(dir, e.Name()), e.Name())})
	}
	sort.Slice(docs, func(i, j int) bool { return docs[i].Title < docs[j].Title })
	return append(out, docs...)
}

// readDoc returns the Markdown of one documentation page. The name is sanitized
// to a single file in DocsDir so it cannot escape (path traversal).
func (m *Manager) readDoc(name string) ([]byte, bool) {
	if name == "" || name == builtinQuickstartName {
		return []byte(builtinQuickstart), true
	}
	base := filepath.Base(name)
	if base != name || !strings.HasSuffix(strings.ToLower(base), ".md") || m.cfg.DocsDir == "" {
		return nil, false
	}
	data, err := os.ReadFile(filepath.Join(m.cfg.DocsDir, base))
	if err != nil {
		return nil, false
	}
	return data, true
}

// docTitle extracts a page title from the first level-1 Markdown heading, or
// falls back to the file name.
func docTitle(path, fallback string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return fallback
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "# ") {
			return strings.TrimSpace(line[2:])
		}
	}
	return fallback
}
