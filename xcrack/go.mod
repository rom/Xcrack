module github.com/rom/xcrack

go 1.25.5

require (
	github.com/coreos/go-oidc/v3 v3.17.0
	github.com/google/go-tpm v0.9.3
	github.com/klauspost/compress v1.19.0
	github.com/rom/xcrypto v0.0.0
	github.com/rom/xfileformats v0.0.0
	golang.org/x/oauth2 v0.34.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/andybalholm/brotli v1.2.2 // indirect
	github.com/bodgit/plumbing v1.3.0 // indirect
	github.com/bodgit/sevenzip v1.6.5 // indirect
	github.com/bodgit/windows v1.0.1 // indirect
	github.com/go-jose/go-jose/v4 v4.1.4 // indirect
	github.com/hashicorp/golang-lru/v2 v2.0.7 // indirect
	github.com/nwaples/rardecode/v2 v2.4.5 // indirect
	github.com/pierrec/lz4/v4 v4.1.27 // indirect
	github.com/spf13/afero v1.15.0 // indirect
	github.com/stangelandcl/ppmd v0.1.1 // indirect
	github.com/ulikunitz/xz v0.5.17 // indirect
	go4.org v0.0.0-20260112195520-a5071408f32f // indirect
	golang.org/x/crypto v0.53.0 // indirect
	golang.org/x/sys v0.46.0 // indirect
	golang.org/x/text v0.40.0 // indirect
)

replace (
	github.com/rom/xcrypto => ../xcrypto
	github.com/rom/xfileformats => ../xfileformats
)
