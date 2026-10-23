package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// These tests pin that the shared inspected-H2 server's limits actually reach a
// conn served through serveConn — on BOTH x/net server implementations (the
// original http2/server.go and the Go 1.27 net/http-wrapping server_wrap.go). The
// two implementations take their limits from different places (BaseConfig vs the
// ConfigureServer'd base), so a wiring that suits one can silently drop limits on
// the other. They talk to the server with a raw http2.Framer so the evidence is
// the server's own SETTINGS and responses, not a client that pre-filters against
// them.

// h2RawPeer is a minimal raw HTTP/2 client: preface + SETTINGS written, the
// server's first SETTINGS read and ACKed.
type h2RawPeer struct {
	conn     net.Conn
	fr       *http2.Framer
	settings map[http2.SettingID]uint32
}

func newH2RawPeer(t *testing.T, conn net.Conn) *h2RawPeer {
	t.Helper()
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	if _, err := io.WriteString(conn, http2.ClientPreface); err != nil {
		t.Fatalf("write preface: %v", err)
	}
	p := &h2RawPeer{conn: conn, fr: http2.NewFramer(conn, conn), settings: map[http2.SettingID]uint32{}}
	p.fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	if err := p.fr.WriteSettings(); err != nil {
		t.Fatalf("write settings: %v", err)
	}
	for {
		f, err := p.fr.ReadFrame()
		if err != nil {
			t.Fatalf("read server SETTINGS: %v", err)
		}
		sf, ok := f.(*http2.SettingsFrame)
		if !ok || sf.IsAck() {
			continue
		}
		if err := sf.ForeachSetting(func(s http2.Setting) error {
			p.settings[s.ID] = s.Val
			return nil
		}); err != nil {
			t.Fatalf("parse server SETTINGS: %v", err)
		}
		break
	}
	if err := p.fr.WriteSettingsAck(); err != nil {
		t.Fatalf("ack server settings: %v", err)
	}
	return p
}

// request sends one GET on streamID padded with padBytes of extra header values
// (split into 2 KiB fields, so the header LIST exceeds a cap without any single
// string tripping the decoder's per-string limit, which is a connection error) and
// returns the response :status, or "RST_STREAM"/"GOAWAY" if the server ended the
// stream or the connection instead.
func (p *h2RawPeer) request(t *testing.T, streamID uint32, padBytes int) string {
	t.Helper()
	fields := []hpack.HeaderField{
		{Name: ":method", Value: http.MethodGet},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: "origin.test"},
		{Name: ":path", Value: "/"},
	}
	for i := 0; padBytes > 0; i++ {
		n := min(padBytes, 2<<10)
		fields = append(fields, hpack.HeaderField{Name: fmt.Sprintf("x-pad-%d", i), Value: strings.Repeat("a", n)})
		padBytes -= n
	}
	var block bytes.Buffer
	enc := hpack.NewEncoder(&block)
	for _, hf := range fields {
		if err := enc.WriteField(hf); err != nil {
			t.Fatalf("hpack encode: %v", err)
		}
	}
	if err := p.fr.WriteHeaders(http2.HeadersFrameParam{
		StreamID: streamID, BlockFragment: block.Bytes(), EndStream: true, EndHeaders: true,
	}); err != nil {
		t.Fatalf("write headers: %v", err)
	}
	for {
		f, err := p.fr.ReadFrame()
		if err != nil {
			t.Fatalf("read response on stream %d: %v", streamID, err)
		}
		if _, ok := f.(*http2.GoAwayFrame); ok {
			return "GOAWAY"
		}
		if f.Header().StreamID != streamID {
			continue
		}
		switch ff := f.(type) {
		case *http2.MetaHeadersFrame:
			return ff.PseudoValue("status")
		case *http2.RSTStreamFrame:
			return "RST_STREAM"
		}
	}
}

// TestH2InspectServe_AdvertisesProductionCaps pins that a conn served by the
// production shared server advertises the production per-connection caps. Both
// h2MaxConcurrentStreams (32) and h2MaxReadFrameSize (1 MiB) differ from the
// library defaults (250 / 16 KiB), so a dropped srv config fails here.
func TestH2InspectServe_AdvertisesProductionCaps(t *testing.T) {
	sh := newH2InspectServer()
	cli, srvConn := h2TCPPair(t)
	go sh.serveConn(context.Background(), srvConn, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	p := newH2RawPeer(t, cli)

	if got := p.settings[http2.SettingMaxConcurrentStreams]; got != h2MaxConcurrentStreams {
		t.Errorf("SETTINGS_MAX_CONCURRENT_STREAMS = %d, want h2MaxConcurrentStreams %d", got, h2MaxConcurrentStreams)
	}
	if got := p.settings[http2.SettingMaxFrameSize]; got != h2MaxReadFrameSize {
		t.Errorf("SETTINGS_MAX_FRAME_SIZE = %d, want h2MaxReadFrameSize %d", got, h2MaxReadFrameSize)
	}
	assertH2HeaderListSize(t, p.settings, h2MaxHeaderBytes)
	if got := p.request(t, 1, 16); got != "204" {
		t.Fatalf("small request status = %q, want 204", got)
	}
}

// TestH2InspectServe_HeaderCapComesFromBaseServer is the negative control for the
// header-list cap. h2MaxHeaderBytes equals net/http's DefaultMaxHeaderBytes, so a
// wiring that dropped the base server (the original implementation substitutes a
// zero http.Server for a nil BaseConfig) would be invisible with production values.
// Lowering the base server's MaxHeaderBytes on a LOCAL instance makes the source of
// the cap observable: it must be advertised AND enforced (431) on the served conn.
func TestH2InspectServe_HeaderCapComesFromBaseServer(t *testing.T) {
	const capBytes = 16 << 10
	sh := newH2InspectServer()
	sh.base.MaxHeaderBytes = capBytes // before any conn is served: no concurrent reader
	cli, srvConn := h2TCPPair(t)
	go sh.serveConn(context.Background(), srvConn, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	p := newH2RawPeer(t, cli)

	assertH2HeaderListSize(t, p.settings, capBytes)
	if got := p.request(t, 1, 1<<10); got != "204" {
		t.Fatalf("under-cap request status = %q, want 204", got)
	}
	if got := p.request(t, 3, 2*capBytes); got != "431" {
		t.Fatalf("over-cap request status = %q, want 431 (base MaxHeaderBytes not enforced)", got)
	}
}

// TestH2InspectServe_PerConnContext pins that the per-tunnel context passed to
// serveConn is the base of every stream's request context: its values are visible
// and its cancellation reaches an in-flight handler.
func TestH2InspectServe_PerConnContext(t *testing.T) {
	type ctxKey struct{}
	ctx, cancel := context.WithCancel(context.WithValue(context.Background(), ctxKey{}, "tunnel-ctx"))
	defer cancel()
	sh := newH2InspectServer()
	gotVal := make(chan any, 1)
	canceled := make(chan struct{})
	cc, _ := h2cLoopback(t, ctx, sh, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotVal <- r.Context().Value(ctxKey{})
		<-r.Context().Done()
		close(canceled)
	}))
	go func() {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://origin.test/ctx", http.NoBody)
		if resp, err := cc.RoundTrip(req); err == nil {
			_ = resp.Body.Close()
		}
	}()
	select {
	case v := <-gotVal:
		if v != "tunnel-ctx" {
			t.Fatalf("stream context value = %v, want the per-tunnel context's value", v)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("handler did not run within 10s")
	}
	cancel()
	select {
	case <-canceled:
	case <-time.After(10 * time.Second):
		t.Fatal("cancelling the per-tunnel context did not cancel the in-flight stream within 10s")
	}
}

// assertH2HeaderListSize checks SETTINGS_MAX_HEADER_LIST_SIZE is derived from
// maxHeaderBytes. Both implementations pad the net/http value by a small fixed
// per-field allowance (10 x 32 bytes today); the bounded window tolerates that
// padding while still telling a 16 KiB cap from the 1 MiB default.
func assertH2HeaderListSize(t *testing.T, settings map[http2.SettingID]uint32, maxHeaderBytes int) {
	t.Helper()
	got, ok := settings[http2.SettingMaxHeaderListSize]
	if !ok {
		t.Fatalf("server did not advertise SETTINGS_MAX_HEADER_LIST_SIZE")
	}
	if lo, v := int64(maxHeaderBytes), int64(got); v < lo || v > lo+1024 {
		t.Fatalf("SETTINGS_MAX_HEADER_LIST_SIZE = %d, want within [%d, %d] (derived from base MaxHeaderBytes)", got, maxHeaderBytes, maxHeaderBytes+1024)
	}
}
