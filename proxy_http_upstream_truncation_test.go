package main

// CHAOS-11 (Codex P1 regression pin): a parent proxy that returns valid
// headers and then truncates the response body must be CHARGED by the
// breaker, not credited. Pre-fix, success was recorded immediately after
// client.Do — before the body was consumed — so a parent failing this way on
// every request reset its own failure count and could never be ejected.

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// truncatingParent is a fake HTTP parent proxy: it reads the request headers,
// answers 200 with a Content-Length larger than the bytes it sends, then
// closes the connection (headers OK, body truncated).
func truncatingParent(t *testing.T) string {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				for {
					line, err := br.ReadString('\n')
					if err != nil || line == "\r\n" || line == "\n" {
						break
					}
				}
				_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 4096\r\n\r\ntruncated"))
			}(conn)
		}
	}()
	return ln.Addr().String()
}

func TestHandleHTTP_TruncatedParentBodyChargesBreaker(t *testing.T) {
	snapshotUpstreamPool(t)
	origPtr := upstreamTransportPtr.Load()
	defer upstreamTransportPtr.Store(origPtr)

	upstreamPool.Configure([]UpstreamEntry{{URL: "http://" + truncatingParent(t)}}, 2, time.Minute)
	applyUpstreamProxy()

	for i := 1; i <= 2; i++ {
		rr := httptest.NewRecorder()
		// The target host is irrelevant — the fake parent answers everything.
		handleHTTP(rr, httptest.NewRequest(http.MethodGet, "http://origin.invalid/file.bin", http.NoBody), ProxyIdentity{})
		if rr.Code != http.StatusOK {
			t.Fatalf("request %d: parent sent valid headers, want 200 to the client, got %d", i, rr.Code)
		}
	}
	st := upstreamPool.List()
	if len(st) != 1 || st[0].Circuit != "open" {
		t.Fatalf("breaker after 2 truncated bodies = %+v, want circuit=open (pre-fix: success reset it before the body was read)", st)
	}
}
