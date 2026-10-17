// Command inspect-tree embeds Xcrack for identification only: it runs the
// recursive decomposition with NO candidates, so nothing is cracked — encrypted
// nodes come back "locked" — and prints the structure of a (possibly nested)
// container as an indented tree with each node's format, status, size and
// content hash. It shows traversing the Result/Node tree and reading a node's
// bytes through the ContentRef, the read-only counterpart to a crack run.
//
// Usage:
//
//	inspect-tree <file>
package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/rom/xcrack/pkg/xcrack"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: inspect-tree <file>")
		os.Exit(2)
	}
	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "read: %v\n", err)
		os.Exit(1)
	}

	// No candidate source => identify only (encrypted nodes stay locked).
	res, err := xcrack.Process(context.Background(), bytes.NewReader(data), int64(len(data)), nil, xcrack.Options{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "process: %v\n", err)
		os.Exit(1)
	}
	defer res.Close()

	var anyLocked bool
	var walk func(n *xcrack.Node, depth int)
	walk = func(n *xcrack.Node, depth int) {
		name := n.Path
		if i := strings.LastIndex(name, "/"); i >= 0 {
			name = name[i+1:]
		}
		if name == "" {
			name = "(root)"
		}
		line := fmt.Sprintf("%s%s  [%s", strings.Repeat("  ", depth), name, n.Status)
		if n.Format != "" {
			line += " " + n.Format
		}
		if n.WasEncrypted {
			line += " encrypted"
		}
		if n.Content != nil {
			sum := n.Content.SHA256()
			line += fmt.Sprintf(" %dB sha256=%s", n.Content.Size(), hex.EncodeToString(sum[:4]))
		}
		line += "]"
		fmt.Println(line)
		if n.Status == xcrack.StatusLocked {
			anyLocked = true
		}
		for _, c := range n.Children {
			walk(c, depth+1)
		}
	}
	walk(res.Root, 0)

	s := res.Stats
	fmt.Printf("\n%d node(s), %d bytes extracted, %s\n", s.FilesSeen, s.BytesExtracted, s.Elapsed.Round(1e6))
	if anyLocked {
		fmt.Println("note: one or more nodes are encrypted (locked); run a crack to recover them")
		os.Exit(1)
	}
}
