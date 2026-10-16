# ADR-0001 — Pure-Go implementation, no external binaries

Status: Accepted · Serves: QA-2, QA-3, QA-12, CON-1

## Context
Xcrack must decrypt untrusted, potentially weaponised files and run embedded
inside the long-lived Impex service. We could implement format support by
reimplementing the crypto in Go, by shelling out to existing tools
(`qpdf`, `libreoffice`, John the Ripper's `*2john` + `john`/`hashcat`), or by a
hybrid of both.

## Decision
Implement **everything in pure Go**, with **no external binaries and no cgo by
default**. Format support derives keys and moves bytes only; it never hands a
file to an application that could interpret it.

## Options considered
1. **Orchestrate external tools.** Fast to assemble, broad format coverage.
   Rejected: heavy runtime deps; weak as an embeddable library; and —
   decisively — opening a hostile document in LibreOffice/Office/a PDF renderer
   can *detonate* macros or exploits inside the Impex host (violates QA-2).
2. **Hybrid (native tier-1 + optional external backend).** Considered earlier;
   rejected after the Impex use case made "never execute content" a hard
   requirement — an optional detonating backend is still a liability.
3. **Pure Go (chosen).** More implementation effort per format, but yields a
   static, cross-compilable, dependency-light, embeddable, and — above all —
   non-executing tool.

## Consequences
- **+** No content execution path exists (strong QA-2). Single static binary /
  pure-Go import (QA-3, QA-12). No external-process management, versioning, or
  sandboxing burden.
- **+** The crypto surface is fully under test (known-answer + fuzz).
- **−** Each format's KDF/cipher/container must be implemented and maintained by
  us; breadth grows slower than "shell out" would.
- **−** No GPU acceleration in the default build (pure Go, CPU-only) — accepted
  (see ASR non-goals); relaxed only for the opt-in server tier below.
- cgo may be revisited *only* for an optional, clearly-isolated performance
  primitive, never for parsing or opening content.

## Amendment (2026) — opt-in server-tier GPU/OpenCL exception

The one sanctioned use of the cgo escape hatch above: an **optional OpenCL
acceleration tier for the `xcrackd` server**, in `xcrack/pkg/accel`.

- **Default build is unchanged.** Every `go build` / `go test` and all of CI
  produce a pure-Go, cgo-free binary: the `accel` package's default file
  (`//go:build !opencl`) has no cgo and reports "not built". The GPU backend
  (`//go:build opencl`, cgo + `-lOpenCL`) is compiled in only when an operator
  explicitly builds `xcrackd` with `-tags opencl` on a host with an OpenCL SDK.
  CI never builds or runs it.
- **Hardware-gated and verifiable.** `xcrackd --gpu` uses the tier only if a
  usable OpenCL device is present, and `--gpu-selftest` (or the automatic
  self-test on `--gpu`) proves the kernel's PBKDF2-HMAC-SHA1 output is
  byte-for-byte identical to the Go reference before any result is trusted;
  otherwise it logs why and falls back to the CPU engine.
- **Scope respects the hard rule.** The accelerator only derives keys
  (PBKDF2-HMAC-SHA1, the shared KDF); it never parses or opens file content, so
  QA-2 ("never execute content") is untouched. It lives in the server tier
  only, never in the embeddable library's default path.

This keeps the pure-Go, non-executing, single-static-binary guarantees for
every default consumer while letting a dedicated server optionally exploit GPU
hardware it happens to have. Live per-scheme routing of the crack loop's KDF
through this primitive is a follow-up; the primitive itself is implemented and
validated.
