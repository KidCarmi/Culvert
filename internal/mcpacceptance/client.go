package mcpacceptance

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// mcpTLSClient builds an HTTPS client that trusts the fixture CA and, when
// withClientCert is set, presents the mTLS client certificate. It NEVER disables
// certificate verification (no InsecureSkipVerify) — the fixture trust root is
// explicit.
func mcpTLSClient(caPEM []byte, clientCert, clientKey string, withClientCert bool, timeout time.Duration) (*http.Client, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("acceptance: could not load fixture CA")
	}
	tc := &tls.Config{
		RootCAs:    pool,
		ServerName: "127.0.0.1",
		MinVersion: tls.VersionTLS12,
	}
	if withClientCert {
		cert, err := tls.LoadX509KeyPair(clientCert, clientKey)
		if err != nil {
			return nil, fmt.Errorf("acceptance: load client cert: %w", err)
		}
		tc.Certificates = []tls.Certificate{cert}
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: &http.Transport{TLSClientConfig: tc, DisableKeepAlives: true},
	}, nil
}

// plainClient is an HTTP (no TLS) client for the admin UI (-ui-no-tls) and the
// proxy-port /metrics endpoint.
func plainClient(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout, Transport: &http.Transport{DisableKeepAlives: true}}
}

// httpResult is the bounded outcome of one request (never carries the token).
type httpResult struct {
	status       int
	body         []byte
	sessionID    string
	tlsError     bool // the TLS handshake itself failed (mTLS rejection)
	transportErr string
}

// jsonrpcEnvelope is the bounded JSON-RPC response we parse.
type jsonrpcEnvelope struct {
	Error *struct {
		Code    int             `json:"code"`
		Message string          `json:"message"`
		Data    json.RawMessage `json:"data"`
	} `json:"error"`
	Result json.RawMessage `json:"result"`
}

// mcpPost issues one authenticated MCP POST to a server over the real TLS
// listener with the allowed application Host. Host-rejection cases use mcpPostRaw.
func mcpPost(ctx context.Context, cli *http.Client, mcpPort int, serverID, token, sessionID, body string) httpResult {
	url := fmt.Sprintf("https://127.0.0.1:%d/mcp/gateway/%s", mcpPort, serverID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader([]byte(body)))
	if err != nil {
		return httpResult{transportErr: "build_request"}
	}
	req.Host = "gw.test"
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("MCP-Protocol-Version", "2025-11-25")
	if sessionID != "" {
		req.Header.Set("Mcp-Session-Id", sessionID)
	}
	resp, err := cli.Do(req)
	if err != nil {
		// A TLS/handshake failure (e.g. mTLS reject) surfaces here.
		return httpResult{tlsError: true, transportErr: classifyTransport(err)}
	}
	defer resp.Body.Close() //nolint:errcheck // best-effort close of a read-only handle
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return httpResult{status: resp.StatusCode, body: raw, sessionID: resp.Header.Get("Mcp-Session-Id")}
}

// mcpPostRaw issues a POST with caller-controlled headers (Host/Origin/version) for
// host/origin/protocol acceptance. extra headers override defaults.
func mcpPostRaw(ctx context.Context, cli *http.Client, mcpPort int, path, token, body string, headers map[string]string) httpResult {
	url := fmt.Sprintf("https://127.0.0.1:%d%s", mcpPort, path)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader([]byte(body)))
	if err != nil {
		return httpResult{transportErr: "build_request"}
	}
	req.Host = "gw.test"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("MCP-Protocol-Version", "2025-11-25")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for k, v := range headers {
		if k == "Host" {
			req.Host = v
			continue
		}
		req.Header.Set(k, v)
	}
	resp, err := cli.Do(req)
	if err != nil {
		return httpResult{tlsError: true, transportErr: classifyTransport(err)}
	}
	defer resp.Body.Close() //nolint:errcheck // best-effort close of a read-only handle
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return httpResult{status: resp.StatusCode, body: raw, sessionID: resp.Header.Get("Mcp-Session-Id")}
}

// mcpGet issues a GET (e.g. protected-resource metadata) over the real listener.
func mcpGet(ctx context.Context, cli *http.Client, mcpPort int, path, host string) httpResult {
	url := fmt.Sprintf("https://127.0.0.1:%d%s", mcpPort, path)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return httpResult{transportErr: "build_request"}
	}
	req.Host = host
	resp, err := cli.Do(req)
	if err != nil {
		return httpResult{tlsError: true, transportErr: classifyTransport(err)}
	}
	defer resp.Body.Close() //nolint:errcheck // best-effort close of a read-only handle
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return httpResult{status: resp.StatusCode, body: raw}
}

// initSession runs initialize + notifications/initialized against a server (with
// the allowed application Host) and returns the negotiated session id.
func initSession(ctx context.Context, cli *http.Client, mcpPort int, serverID, token string) (string, httpResult) {
	init := mcpPost(ctx, cli, mcpPort, serverID, token, "",
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}`)
	if init.status != 200 || init.sessionID == "" {
		return "", init
	}
	_ = mcpPost(ctx, cli, mcpPort, serverID, token, init.sessionID,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	return init.sessionID, init
}

// adminGet issues an authenticated GET to the admin API (plain HTTP, -ui-no-tls).
func adminGet(ctx context.Context, cli *http.Client, uiPort int, user, pass, path string) httpResult {
	url := fmt.Sprintf("http://127.0.0.1:%d%s", uiPort, path)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return httpResult{transportErr: "build_request"}
	}
	if user != "" {
		req.SetBasicAuth(user, pass)
	}
	resp, err := cli.Do(req)
	if err != nil {
		return httpResult{transportErr: classifyTransport(err)}
	}
	defer resp.Body.Close() //nolint:errcheck // best-effort close of a read-only handle
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return httpResult{status: resp.StatusCode, body: raw}
}

// proxyHealth probes the SWG forward proxy's own /health endpoint on the proxy
// port (distinct from the admin UI on the ui-port). Used to prove the SWG stays up
// during emergency-disable of the MCP listener.
func proxyHealth(ctx context.Context, cli *http.Client, proxyPort int) httpResult {
	url := fmt.Sprintf("http://127.0.0.1:%d/health", proxyPort)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return httpResult{transportErr: "build_request"}
	}
	resp, err := cli.Do(req)
	if err != nil {
		return httpResult{transportErr: classifyTransport(err)}
	}
	defer resp.Body.Close() //nolint:errcheck // best-effort close of a read-only handle
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	return httpResult{status: resp.StatusCode, body: raw}
}

// metricsGet scrapes /metrics from the proxy port with the bearer token.
func metricsGet(ctx context.Context, cli *http.Client, proxyPort int, token string) httpResult {
	url := fmt.Sprintf("http://127.0.0.1:%d/metrics", proxyPort)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return httpResult{transportErr: "build_request"}
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := cli.Do(req)
	if err != nil {
		return httpResult{transportErr: classifyTransport(err)}
	}
	defer resp.Body.Close() //nolint:errcheck // best-effort close of a read-only handle
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return httpResult{status: resp.StatusCode, body: raw}
}

// reasonOf extracts the JSON-RPC error.message (a stable reason code) or "".
func reasonOf(body []byte) string {
	var env jsonrpcEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		return ""
	}
	if env.Error != nil {
		return env.Error.Message
	}
	return ""
}

// hasResult reports whether the JSON-RPC envelope carries a result member.
func hasResult(body []byte) bool {
	var env jsonrpcEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		return false
	}
	return env.Result != nil
}

// classifyTransport reduces a transport error to a bounded label (never a raw
// address or secret).
func classifyTransport(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	switch {
	case containsAny(s, "certificate required", "tls: certificate required", "bad certificate", "handshake failure"):
		return "tls_client_cert_required"
	case containsAny(s, "context deadline exceeded", "Client.Timeout"):
		return "timeout"
	case containsAny(s, "connection refused"):
		return "connection_refused"
	case containsAny(s, "tls:"):
		return "tls_error"
	default:
		return "transport_error"
	}
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if bytes.Contains([]byte(s), []byte(sub)) {
			return true
		}
	}
	return false
}
