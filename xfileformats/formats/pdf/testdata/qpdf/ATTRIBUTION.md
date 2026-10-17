# Provenance: qpdf cross-validation PDFs

These PDF files are the committed, deterministic gold standard for the PDF
scheme. They were produced by **qpdf** (http://qpdf.sourceforge.net/,
Apache-2.0), encrypting a tiny plaintext PDF under each supported algorithm.

They are qpdf *output documents*, not qpdf source, so no third-party source
licence attaches to them; they are regenerable with the commands below and are
committed so the cross-validation runs even when qpdf is not installed (the live
path `TestQPDFCrossValidation`, gated by `XCRACK_QPDF_LIVE=1`, re-generates and
re-checks against the installed `qpdf`).

| File(s) | Algorithm (PDF revision) |
| ------- | ------------------------ |
| `rc4-40.pdf` | RC4 40-bit (V1/R2) |
| `rc4-128.pdf` | RC4 128-bit (V2/R3) |
| `aes-128.pdf` | AESV2 (V4/R4) |
| `aes-256-00.pdf` … `aes-256-15.pdf` | AES-256 (V5/R6), 16 different salts |

- **User password:** `userpw`
- **Owner password:** `ownerpw`
- **Plaintext marker (decryption check):** `CROSSCHECK-MARKER-7f3a1`

The 16 R6 salts are deliberately kept: they are what originally caught an
off-by-one in the ISO 32000-2 Algorithm 2.B hash loop. Consumed by
`../../qpdf_test.go` (`TestQPDFVectors`). Indexed in `/gold/README.md`.
