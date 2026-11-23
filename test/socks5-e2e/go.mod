// Real-network SOCKS5 verification suite (SWG-901). A separate module so its
// test-only dependencies (the gldap LDAP server) never enter the shipped
// gateway's go.mod. Not built by the root module's ./... patterns.
module github.com/KidCarmi/Culvert/test/socks5-e2e

go 1.27.0

require (
	github.com/jimlambrt/gldap v0.1.14
	golang.org/x/net v0.62.0
)

require (
	github.com/Azure/go-ntlmssp v0.0.0-20221128193559-754e69321358 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/fatih/color v1.17.0 // indirect
	github.com/go-asn1-ber/asn1-ber v1.5.7 // indirect
	github.com/go-ldap/ldap/v3 v3.4.8 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/hashicorp/go-hclog v1.6.3 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/stretchr/testify v1.9.0 // indirect
	golang.org/x/crypto v0.58.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
