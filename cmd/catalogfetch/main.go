// Command catalogfetch performs an HTTP GET of a release-catalog object using the
// SAME client shape the production catalog fetcher uses (release_catalog_http.go):
// HTTP/2 attempted and a self-identifying User-Agent.
//
// Why this exists instead of curl: the live catalog origin
// (catalog.culvertlabs.com) is fronted by Cloudflare bot management, which
// fingerprints the TLS/HTTP2 client — NOT just the User-Agent header — and 403s
// curl even when curl sends the matching UA (two prior CI fixes added the UA and
// dropped Cache-Control and it still 403'd). The Go net/http client's fingerprint
// is accepted; it is the known-good shape TestServedVerify_BakedRootGate already
// relies on. CI convergence/confirm checks therefore fetch through this tool.
//
// Usage:
//
//	go run ./cmd/catalogfetch [-raw] [-timeout 30s] <url>
//
// Prints the lowercase-hex SHA-256 of the response body (matching
// `sha256sum | awk '{print $1}'`), or the raw body with -raw. Exits non-zero on a
// transport error or any non-200 status, so a caller can guard with `|| VAR=""`.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"
)

// catalogUserAgent must stay byte-equal to catalogUserAgent in
// release_catalog_http.go (the known-good, non-403'd request shape). It is
// duplicated here because a subdirectory command cannot import package main;
// the workflows carry the same string in their CATALOG_UA env for the same reason.
const catalogUserAgent = "Culvert-ReleaseCatalog/1.0 (+https://github.com/KidCarmi/Culvert)"

// maxCatalogBytes bounds the response read (the catalog index is a few KB; this is
// a generous ceiling that still refuses a hostile unbounded body).
const maxCatalogBytes int64 = 32 << 20

func main() {
	raw := flag.Bool("raw", false, "print the raw response body instead of its SHA-256")
	timeout := flag.Duration("timeout", 30*time.Second, "overall request timeout")
	ua := flag.String("ua", catalogUserAgent, "User-Agent to send")
	flag.Parse()
	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: catalogfetch [-raw] [-timeout 30s] <url>")
		os.Exit(2)
	}
	body, err := fetch(flag.Arg(0), *ua, *timeout)
	if err != nil {
		fmt.Fprintln(os.Stderr, "catalogfetch:", err)
		os.Exit(1)
	}
	if *raw {
		_, _ = os.Stdout.Write(body)
		return
	}
	sum := sha256.Sum256(body)
	fmt.Println(hex.EncodeToString(sum[:]))
}

// fetch GETs target with the production client shape and returns the (bounded)
// body. Any non-200 status is an error.
func fetch(target, ua string, timeout time.Duration) ([]byte, error) {
	u, err := url.Parse(target)
	if err != nil {
		return nil, fmt.Errorf("parse url: %w", err)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return nil, fmt.Errorf("url scheme %q must be http or https", u.Scheme)
	}

	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          10,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: time.Second,
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", ua)

	// #nosec G107 -- target is a public catalog URL supplied by the CI step (a
	// literal in the workflow), and its scheme is validated above; this tool
	// exists specifically to fetch that origin with the Go client shape.
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxCatalogBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	if int64(len(data)) > maxCatalogBytes {
		return nil, errors.New("response exceeds the size bound")
	}
	return data, nil
}
