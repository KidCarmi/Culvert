package main

// setup_token.go — a per-instance SETUP TOKEN that gates the one-time
// first-admin bootstrap (POST /api/setup/complete) on the traffic path it is
// actually exposed on.
//
// Until the first admin exists, /api/setup/* is on uiAuthMiddleware's public
// allowlist by necessity, and the admin port is published by docker-compose
// on every interface; a host firewall cannot narrow that window on a Docker
// published port (the traffic traverses FORWARD/NAT, not the host's input
// chain), and "tighten access later" is not protection during the window
// (owner review, PR #1528). So the appliance first boot mints a random token
// per instance, persists it in the stack's .env (root-only) and hands it to
// the proxy as CULVERT_SETUP_TOKEN; the proxy then refuses to create the
// first admin unless the request presents it. The token is shown to the
// operator on the hypervisor console and via `sudo culvert-status` — both
// already-privileged surfaces — never over the network.
//
// Rules:
//   - The env is read ONCE at startup (initAuth shim); an unset or blank value
//     keeps the historical behaviour byte for byte (no token required).
//   - Only the SHA-256 of the token is kept in memory and the comparison is
//     constant-time, so a lookup cannot leak the token's bytes or length.
//   - The token is presented in the X-Culvert-Setup-Token header — not in the
//     JSON body — so the SetInitialAdmin schema and its conformance tests are
//     untouched and the secret never lands in a body-level audit diff.
//   - A wrong or missing token counts as a setup failure in the per-IP pair
//     limiter (the token is 128 bits, the limiter is defence in depth).
//   - Once setup is complete the token is irrelevant: IsConfigured() wins and
//     the endpoint answers 403 regardless.

import (
	"crypto/sha256"
	"crypto/subtle"
	"strings"
	"sync"
)

// headerSetupToken is the request header carrying the setup token.
const headerSetupToken = "X-Culvert-Setup-Token" // #nosec G101 -- header NAME, not a credential; the token value is per-instance and never in source

var setupTokenState struct {
	mu   sync.RWMutex
	hash [sha256.Size]byte
	set  bool
}

// loadSetupToken installs the startup-scoped token. A blank value clears it.
func loadSetupToken(raw string) {
	v := strings.TrimSpace(raw)
	setupTokenState.mu.Lock()
	defer setupTokenState.mu.Unlock()
	if v == "" {
		setupTokenState.set = false
		setupTokenState.hash = [sha256.Size]byte{}
		return
	}
	setupTokenState.hash = sha256.Sum256([]byte(v))
	setupTokenState.set = true
}

// setupTokenRequired reports whether first-admin setup needs the token.
func setupTokenRequired() bool {
	setupTokenState.mu.RLock()
	defer setupTokenState.mu.RUnlock()
	return setupTokenState.set
}

// setupTokenAccepts reports whether presented matches the configured token.
// It returns true when no token is configured (nothing to enforce) and
// compares digests in constant time otherwise.
func setupTokenAccepts(presented string) bool {
	setupTokenState.mu.RLock()
	defer setupTokenState.mu.RUnlock()
	if !setupTokenState.set {
		return true
	}
	got := sha256.Sum256([]byte(strings.TrimSpace(presented)))
	return subtle.ConstantTimeCompare(got[:], setupTokenState.hash[:]) == 1
}
