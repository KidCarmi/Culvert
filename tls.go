package main

// tls.go — package-main glue for the admin-UI self-signed certificate
// generator, moved to internal/uitls (ADR-0002). The uiExtraSANs global stays
// here because the ui_extras startup slice and admin-settings persistence
// (admin_settings.go) own it; selfSignedTLS passes it to the engine as a
// parameter.

import (
	"crypto/tls"

	"github.com/KidCarmi/Culvert/internal/uitls"
)

// uiExtraSANs holds additional SANs for the self-signed UI TLS cert,
// set from --ui-san flag / proxy.ui_sans config before startUI() is called.
var uiExtraSANs []string

// selfSignedTLS generates a self-signed TLS certificate that includes all
// local network interface IPs (so remote access via private/Docker IPs works)
// plus any extra SANs from uiExtraSANs (--ui-san / config).
func selfSignedTLS() (*tls.Config, error) {
	return uitls.SelfSigned(uiExtraSANs)
}
