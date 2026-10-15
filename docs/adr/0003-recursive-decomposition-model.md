# ADR-0003 — Recursive decomposition with a result tree

Status: Accepted · Serves: QA-7, FR-4, FR-5, FR-8

## Context
Malware is routinely nested: a password-protected ZIP holds an encrypted
`.docx`, which holds another archive, and so on. Impex needs the *real* leaf
content at every layer, plus the password that unlocked each layer. Two
designs: Xcrack decrypts one layer and lets Impex re-submit inner files, or
Xcrack owns the recursion and returns a tree.

## Decision
Xcrack **owns the recursion**. Each file is modelled as a layer that may be an
*encryption layer* (decrypt) and/or a *container layer* (unpack). The engine
recurses to bounded depth, producing a **tree of `Node`s**, each carrying its
detected format, the password used (if any), its decrypted content, its
children, and a status. A password that unlocks an ancestor is **promoted** to
the front of candidates for descendants.

## Options considered
1. **One layer, caller re-submits.** Narrow and simple for Xcrack, but pushes
   archive-walking, password promotion, and budget accounting onto every caller,
   and loses the unified tree/manifest. Rejected given Impex explicitly wants
   multi-layer handling.
2. **Own the recursion, return a tree (chosen).** Correct layering, one place for
   budgets/cycle-detection/promotion, a faithful result to hand the scanner.

## Consequences
- **+** One coherent result (QA-7, FR-4/5); promotion cuts work on reused
  passwords (FR-8).
- **+** Budgets, cycle detection, and spill are enforced centrally.
- **−** Xcrack must implement container walking and own the safety budget for
  unbounded nesting — this is the single largest safety surface (see
  [ADR-0004](0004-hostile-input-safety-budgets.md)).
- Documents are leaves by default to keep the boundary clean
  ([ADR-0007](0007-documents-as-leaves.md)).
