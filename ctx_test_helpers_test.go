package main

// Shared context-aware wrappers for the E2E/traffic test suites. golangci-lint's
// noctx linter forbids the context-free stdlib calls (net.Listen, net.DialTimeout,
// http.Client.Get, http.NewRequest) even in tests; these thin helpers carry a
// background context so the call sites stay readable. dialTimeout lives in
// mitm_inspect_e2e_test.go (same package) and is reused here.

import (
	"context"
	"net"
	"net/http"
)

// ctxListen replaces net.Listen (noctx) for loopback tcp test listeners.
func ctxListen(addr string) (net.Listener, error) {
	return (&net.ListenConfig{}).Listen(context.Background(), "tcp", addr)
}

// ctxGet issues a GET through the client with a background context (noctx wants
// Client.Do over Client.Get).
func ctxGet(client *http.Client, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, err
	}
	return client.Do(req)
}
