package main

// socks5_bind_address.go — the opt-in SOCKS5 bind address (SWG-901 follow-up,
// proposal decision D10).
//
// The SOCKS5 listener has always bound ":<port>", i.e. every interface. That
// stays the default: with -socks5-bind / proxy.socks5_bind unset the listen
// address is byte-identical to before. An operator who wants the listener on
// one interface only (loopback for a local agent, or a management/VLAN
// address) sets an IP literal.
//
// Only IP literals are accepted. A hostname would make the bound interface a
// function of DNS at boot (and of /etc/hosts ordering for v4 vs v6), so an
// operator who asked for "the internal interface" could silently get another
// one; the same reason the MCP gateway's bind_address takes an IP. An invalid
// value fails startup with an error naming the key, mirroring the port checks.
//
// Startup-only, like -socks5-port itself and the other listener addresses
// (roadmap/FEATURE-COVERAGE.md "Startup-only"): a listener's bind is a
// deployment boundary, not a runtime policy setting, so there is deliberately
// no admin API/UI mutation endpoint (recorded GUI-parity deferral).

import (
	"errors"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
)

// validateSOCKS5BindAddress accepts "" (every interface) or an IP literal.
func validateSOCKS5BindAddress(v string) error {
	if v == "" {
		return nil
	}
	if strings.TrimSpace(v) != v {
		return errors.New("must not contain leading or trailing whitespace")
	}
	if net.ParseIP(v) == nil {
		return fmt.Errorf("must be an IP address literal such as 127.0.0.1 or ::1 (no brackets, port or "+
			"hostname: a hostname would make the bound interface depend on DNS), got %q", v)
	}
	return nil
}

// resolveSOCKS5Bind applies the usual precedence (a non-empty CLI flag wins
// over config.yaml) and validates the resolved value, because the flag
// bypasses FileConfig.validate. Both candidates are trimmed BEFORE the pick so
// a whitespace-only flag cannot shadow a real config.yaml value. Nil-safe for
// tests that build a startupState without the flag.
func resolveSOCKS5Bind(flagVal *string, yamlVal string) (string, error) {
	cli := ""
	if flagVal != nil {
		cli = strings.TrimSpace(*flagVal)
	}
	v := firstStr(cli, strings.TrimSpace(yamlVal))
	if err := validateSOCKS5BindAddress(v); err != nil {
		return "", fmt.Errorf("-socks5-bind/proxy.socks5_bind: %w", err)
	}
	return v, nil
}

// mustResolveSOCKS5Bind is resolveSOCKS5Bind for the boot path. It runs before
// setupLogger, so it exits through log.Fatalf like the port checks beside it.
func mustResolveSOCKS5Bind(flagVal *string, yamlVal string) string {
	v, err := resolveSOCKS5Bind(flagVal, yamlVal)
	if err != nil {
		log.Fatalf("Invalid SOCKS5 bind address: %v", err)
	}
	return v
}

// socks5ListenAddr is the address the supervisor binds. An empty host yields
// ":<port>", the historical every-interface bind.
func socks5ListenAddr(host string, port int) string {
	return net.JoinHostPort(host, strconv.Itoa(port))
}
