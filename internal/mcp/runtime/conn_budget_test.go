package runtime

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// selfSignedTLS returns a server TLS config and the CA pool a client needs.
func selfSignedTLS(t testing.TB) (*tls.Config, *x509.CertPool) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		BasicConstraintsValid: true, IsCA: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: k, Leaf: leaf}},
		MinVersion:   tls.VersionTLS12,
	}, pool
}

// OVN-07. HTTP/2 multiplexing makes MaxConns meaningless as a bound on concurrent
// REQUESTS. ServeTLS auto-enables h2, and one accepted socket can carry hundreds
// of concurrent streams into an admission path sized for MaxConcurrent workers —
// so a single connection could fill the worker pool AND push its surplus into the
// SHARED queue, consuming capacity other connections depend on, while occupying
// exactly one of the MaxConns slots that were supposed to bound it.
//
// (http.Server.HTTP2.MaxConcurrentStreams is deliberately NOT the mechanism: it is
// silently ignored on the ServeTLS auto-h2 path in this toolchain — verified
// empirically, setting it to 8 still admitted 200 concurrent streams — so relying
// on it would be a control that only looks configured.)
//
// Requests are held inside authentication so the pressure is real; a fast-rejecting
// fixture never queues and would prove nothing.
func TestConnBudget_OneConnectionCannotFloodTheSharedQueue(t *testing.T) {
	const workers = 4
	const fired = 40

	k := newESKey(t, "k1")
	deps := testDeps(t, k, nil)
	bk := &blockingKeys{inner: deps.Keys, entered: make(chan struct{}, fired), release: make(chan struct{})}
	deps.Keys = bk

	tlsCfg, pool := selfSignedTLS(t)
	cfg := gwListenerConfig(t)
	cfg.Port = 0
	cfg.TLS = tlsCfg
	cfg.Limits = limitsWithPools(t, workers, 256)

	l, err := newListener(cfg, deps, "budget-gw", 1)
	if err != nil {
		t.Fatalf("newListener: %v", err)
	}
	if err := l.bind(); err != nil {
		t.Fatalf("bind: %v", err)
	}
	l.serve()
	t.Cleanup(func() { l.stop(t.Context()) })

	cli := &http.Client{Timeout: 25 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs: pool, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12,
			NextProtos: []string{"h2"},
		},
		ForceAttemptHTTP2:   true,
		MaxConnsPerHost:     1, // ONE socket: the whole point
		MaxIdleConnsPerHost: 1,
	}}
	base := "https://" + l.netln.Addr().String()

	var peakQueued atomic.Int64
	stop := make(chan struct{})
	var sampler sync.WaitGroup
	sampler.Add(1)
	go func() {
		defer sampler.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			if q := l.ctr.queued.Load(); q > peakQueued.Load() {
				peakQueued.Store(q)
			}
			time.Sleep(200 * time.Microsecond)
		}
	}()

	tok := gwToken(k)
	var wg sync.WaitGroup
	for i := 0; i < fired; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			body := strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
			req, rerr := http.NewRequestWithContext(t.Context(), http.MethodPost, base+gwResource, body)
			if rerr != nil {
				return
			}
			req.Host = gwHost
			req.Header.Set("Authorization", "Bearer "+tok)
			resp, derr := cli.Do(req)
			if derr == nil {
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
			}
		}(i)
	}

	// Wait until the worker pool is genuinely saturated, then read the peak.
	deadline := time.After(10 * time.Second)
	for i := 0; i < workers; i++ {
		select {
		case <-bk.entered:
		case <-deadline:
			close(bk.release)
			wg.Wait()
			t.Fatal("the fixture never saturated the worker pool")
		}
	}
	time.Sleep(400 * time.Millisecond) // let any un-budgeted surplus pile into the queue
	peak := peakQueued.Load()

	close(bk.release)
	wg.Wait()
	close(stop)
	sampler.Wait()

	if peak > int64(workers) {
		t.Fatalf("one connection put %d requests into the SHARED admission queue "+
			"(worker pool is %d): a single socket consumes capacity other connections need", peak, workers)
	}
}
