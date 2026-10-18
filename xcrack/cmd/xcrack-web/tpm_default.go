//go:build !tpm

package main

// tpmBuilt reports whether this binary includes the TPM-sealed found-password
// cache. The default pure-Go build does not; a //go:build tpm build does (see
// tpm_enabled.go). It is surfaced to the UI via webui.Config.TPMBuild.
const tpmBuilt = false
