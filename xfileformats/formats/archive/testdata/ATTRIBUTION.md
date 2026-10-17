# Provenance: header-encrypted archive fixtures

| File | How it was made | Password | Content |
| ---- | --------------- | -------- | ------- |
| `hdr.7z` | `7z a -mhe=on -p…` (p7zip) | `Hunter2` | `secret payload inside an encrypted-header archive\n` |
| `hdr.rar` | `rar a -hp… ` (RARLAB `rar`) | `Hunter2` | `secret payload inside an encrypted-header archive\n` |

These are **locally generated** test artifacts — our own trivial plaintext
packed into a header-encrypted 7z / RAR archive with the standard CLI tools —
not third-party data, so no external licence attaches. They are committed so the
header-encryption decode path (`hdrenc_test.go`) is exercised deterministically
even when `7z` / `rar` are not installed (the live interop tests in
`archive_test.go` additionally drive the real tools when present).

Indexed in `/gold/README.md`.
