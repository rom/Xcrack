module github.com/rom/xcrack

go 1.25.5

require (
	github.com/rom/xcrypto v0.0.0
	github.com/rom/xfileformats v0.0.0
	gopkg.in/yaml.v3 v3.0.1
)

replace (
	github.com/rom/xcrypto => ../xcrypto
	github.com/rom/xfileformats => ../xfileformats
)
