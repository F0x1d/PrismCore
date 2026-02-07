module github.com/apernet/hysteria/mobile/v2

go 1.24.0

toolchain go1.25.1

require (
	github.com/apernet/hysteria/core/v2 v2.0.0-00010101000000-000000000000
	github.com/apernet/hysteria/extras/v2 v2.0.0-00010101000000-000000000000
	github.com/txthinking/socks5 v0.0.0-20230325130024-4230056ae301
)

require (
	github.com/apernet/quic-go v0.57.2-0.20260111184307-eec823306178 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/patrickmn/go-cache v2.1.0+incompatible // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	github.com/stretchr/objx v0.5.2 // indirect
	github.com/stretchr/testify v1.11.1 // indirect
	github.com/txthinking/runnergroup v0.0.0-20210608031112-152c7c4432bf // indirect
	golang.org/x/crypto v0.41.0 // indirect
	golang.org/x/exp v0.0.0-20240506185415-9bf2ced13842 // indirect
	golang.org/x/mobile v0.0.0-20260204172633-1dceadbbeea3 // indirect
	golang.org/x/net v0.43.0 // indirect
	golang.org/x/sys v0.40.0 // indirect
	golang.org/x/text v0.28.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/apernet/hysteria/core/v2 => ../core

replace github.com/apernet/hysteria/extras/v2 => ../extras
