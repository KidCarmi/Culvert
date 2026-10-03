package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/ssrf"
)

// Exercise the real http.Transport request/redirect path. Only the network is
// replaced: Control sees the resolved IP, as it does immediately before the
// production connect. A public forward proxy answers over net.Pipe, so losing
// Proxy=nil makes these tests succeed at reaching a private destination.
func TestOIDCTransport_SSRFBoundary(t *testing.T) {
	for _, backend := range []string{"legacy", "flow", "jwks"} {
		t.Run(backend, func(t *testing.T) {
			for _, target := range []string{
				"http://127.0.0.1/introspect", "http://10.0.0.1/introspect",
				"http://169.254.169.254/introspect", "http://[::1]/introspect",
				"http://[::ffff:127.0.0.1]/introspect", "http://rebind.test/introspect",
			} {
				t.Run(target, func(t *testing.T) {
					hits := installOIDCBoundaryNetwork(t, "")
					err := oidcBoundaryRequest(t, backend, target)
					if !errors.Is(err, ssrf.ErrBlocked) {
						t.Fatalf("private destination must fail at the dial guard, got %v", err)
					}
					if hits.Load() != 0 {
						t.Fatal("request escaped the guard through the public proxy")
					}
				})
			}
			t.Run("redirect to private", func(t *testing.T) {
				hits := installOIDCBoundaryNetwork(t, "http://169.254.169.254/introspect")
				err := oidcBoundaryRequest(t, backend, "http://93.184.216.34/introspect")
				if !errors.Is(err, ssrf.ErrBlocked) || hits.Load() != 1 {
					t.Fatalf("redirect must stop before the private request: err=%v requests=%d", err, hits.Load())
				}
			})
			t.Run("public destination still works", func(t *testing.T) {
				hits := installOIDCBoundaryNetwork(t, "")
				if err := oidcBoundaryRequest(t, backend, "http://93.184.216.34/introspect"); err != nil || hits.Load() != 1 {
					t.Fatalf("public endpoint: err=%v requests=%d", err, hits.Load())
				}
			})
		})
	}
}

func oidcBoundaryRequest(t *testing.T, backend, target string) error {
	t.Helper()
	if backend == "legacy" {
		a, err := NewOIDCAuth(OIDCConfig{IntrospectionURL: target, ClientID: "fixture"})
		if err != nil {
			return err
		}
		defer a.client.CloseIdleConnections()
		id, active, _, err := a.introspect("fixture-token")
		if err == nil && (!active || id == nil || id.Sub != "fixture-subject") {
			return fmt.Errorf("public legacy endpoint did not supply the expected identity")
		}
		return err
	}
	// Use the production flow transport and actual request methods, without
	// network discovery. Constructor wiring is reviewed separately in RISK-002.
	client := &http.Client{Transport: newOIDCTransport(), Timeout: time.Second}
	defer client.CloseIdleConnections()
	if backend == "flow" {
		provider := &OIDCFlowProvider{
			profile: &IdPProfile{ID: "fixture"},
			cfg:     &OIDCProfileConfig{ClientID: "fixture"},
			disc:    &oidcDiscoveryDoc{IntrospectionEndpoint: target},
			client:  client,
		}
		id, active, _, err := provider.introspect("fixture-token")
		if err == nil && (!active || id == nil || id.Sub != "fixture-subject") {
			return fmt.Errorf("public flow endpoint did not supply the expected identity")
		}
		return err
	}
	cache := &jwksCache{jwksURI: target, client: client}
	if err := cache.refresh(); err != nil {
		return err
	}
	if cache.keys["fixture"] == nil {
		return fmt.Errorf("public JWKS endpoint did not populate the cache")
	}
	return nil
}

func installOIDCBoundaryNetwork(t *testing.T, redirect string) *atomic.Int64 {
	t.Helper()
	oldTransport, oldDial := http.DefaultTransport, ssrfSafeDialContext
	t.Cleanup(func() { http.DefaultTransport, ssrfSafeDialContext = oldTransport, oldDial })
	hits := &atomic.Int64{}
	proxyURL, err := url.Parse("http://93.184.216.35:3128")
	if err != nil {
		t.Fatal(err)
	}
	// This is the same Proxy hook that DefaultTransport normally inherits from
	// ProxyFromEnvironment; avoid its process-global environment cache in tests.
	http.DefaultTransport = &http.Transport{Proxy: func(*http.Request) (*url.URL, error) { return proxyURL, nil }}
	ssrfSafeDialContext = func(_ context.Context, network, addr string) (net.Conn, error) {
		if addr == "rebind.test:80" {
			addr = "10.0.0.1:80" // actual resolved IP, rather than the hostname's earlier public answer
		}
		if err := ssrf.Control(network, addr, nil); err != nil {
			return nil, err
		}
		client, server := net.Pipe()
		_ = client.SetDeadline(time.Now().Add(time.Second))
		_ = server.SetDeadline(time.Now().Add(time.Second))
		done := make(chan struct{})
		t.Cleanup(func() { _ = client.Close(); _ = server.Close(); <-done })
		go func() {
			defer close(done)
			defer server.Close()
			req, err := http.ReadRequest(bufio.NewReader(server))
			if err != nil {
				return
			}
			_, _ = io.Copy(io.Discard, req.Body)
			_ = req.Body.Close()
			hits.Add(1)
			if redirect != "" && req.URL.Host != "169.254.169.254" {
				_, _ = fmt.Fprintf(server, "HTTP/1.1 302 Found\r\nLocation: %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", redirect)
				return
			}
			// Parser-only RSA fixture, never used to verify a signature.
			body := `{"active":true,"sub":"fixture-subject","keys":[{"kty":"RSA","kid":"fixture","n":"AQ","e":"AQAB"}]}`
			_, _ = fmt.Fprintf(server, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
		}()
		return client, nil
	}
	return hits
}
