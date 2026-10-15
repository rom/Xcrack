# ADR-0007 — Documents are leaves by default; explosion is opt-in

Status: Accepted · Serves: QA-7, FR-9, CON-3

## Context
Office OOXML files are ZIP archives; legacy `.doc` is an OLE compound file. When
decomposing recursively, should Xcrack explode a decrypted document into its
internal parts (XML, embedded objects, macro streams), or hand the whole
document back as a leaf for Impex to introspect?

## Decision
Treat a decrypted **document as a leaf by default** — decrypt it and return the
intact file. Decomposing a document into parts is **opt-in** via
`--explode-documents` (library: `Options.ExplodeDocuments`). "True archives"
(ZIP-as-archive, 7z, tar, …) are always unpacked when `--recurse` is on.

## Options considered
1. **Always explode documents.** Maximal visibility, but most scanners prefer the
   intact document and can introspect it themselves; exploding by default
   multiplies node counts and surfaces format-internal noise. Rejected as default.
2. **Never explode.** Loses a useful capability for deep inspection. Rejected.
3. **Leaf by default, opt-in explosion (chosen).** Clean boundary; caller decides.

## Consequences
- **+** Predictable, low-noise trees by default; Impex gets whole documents.
- **+** The capability still exists for deep analysis when wanted (FR-9), with
  full CLI/library parity (CON-3).
- **−** The format layer must distinguish "container that is an archive" from
  "container that is a document" — expressed via `Caps.Explodable`.
- Detection is by content (magic/structure), so a `.docx` renamed to `.zip`
  (or vice-versa) is still classified correctly.
