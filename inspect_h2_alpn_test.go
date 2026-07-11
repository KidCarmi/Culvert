package main

import (
	"reflect"
	"testing"
)

// buildClientHello assembles a minimal but structurally-valid TLS ClientHello
// record for exercising parseClientHelloALPN. includeALPN=false omits the ALPN
// extension entirely (an older/ALPN-less client).
func buildClientHello(alpn []string, includeALPN bool) []byte {
	var ext []byte
	if includeALPN {
		var list []byte
		for _, p := range alpn {
			list = append(list, byte(len(p)))
			list = append(list, p...)
		}
		alpnData := []byte{byte(len(list) >> 8), byte(len(list))}
		alpnData = append(alpnData, list...)
		// extension type = ALPN(16) | length | data
		ext = append(ext, 0x00, 0x10, byte(len(alpnData)>>8), byte(len(alpnData)))
		ext = append(ext, alpnData...)
	}
	body := []byte{0x03, 0x03} // legacy_version
	body = append(body, make([]byte, 32)...)
	// session_id(0) | cipher_suites(len2, TLS_AES_128_GCM_SHA256) | compression(len1, null)
	body = append(body, 0x00, 0x00, 0x02, 0x13, 0x01, 0x01, 0x00, byte(len(ext)>>8), byte(len(ext)))
	body = append(body, ext...)

	hs := []byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	hs = append(hs, body...)

	rec := []byte{0x16, 0x03, 0x01, byte(len(hs) >> 8), byte(len(hs))}
	rec = append(rec, hs...)
	return rec
}

func TestParseClientHelloALPN(t *testing.T) {
	t.Run("h2+http11", func(t *testing.T) {
		got, ok := parseClientHelloALPN(buildClientHello([]string{"h2", "http/1.1"}, true))
		if !ok || !reflect.DeepEqual(got, []string{"h2", "http/1.1"}) {
			t.Fatalf("got %v ok=%v, want [h2 http/1.1] ok=true", got, ok)
		}
		if !clientOffersH2(got) {
			t.Fatal("clientOffersH2 must be true when h2 is offered")
		}
	})

	t.Run("http11-only", func(t *testing.T) {
		got, ok := parseClientHelloALPN(buildClientHello([]string{"http/1.1"}, true))
		if !ok || !reflect.DeepEqual(got, []string{"http/1.1"}) {
			t.Fatalf("got %v ok=%v, want [http/1.1] ok=true", got, ok)
		}
		if clientOffersH2(got) {
			t.Fatal("clientOffersH2 must be false for an http/1.1-only offer")
		}
	})

	t.Run("no-alpn-extension", func(t *testing.T) {
		if got, ok := parseClientHelloALPN(buildClientHello(nil, false)); ok {
			t.Fatalf("absent ALPN must return ok=false (caller falls back to http/1.1), got %v", got)
		}
	})

	t.Run("truncated-record", func(t *testing.T) {
		full := buildClientHello([]string{"h2"}, true)
		if _, ok := parseClientHelloALPN(full[:len(full)-3]); ok {
			t.Fatal("a ClientHello not fully buffered must return ok=false (fail closed)")
		}
	})

	t.Run("not-handshake", func(t *testing.T) {
		if _, ok := parseClientHelloALPN([]byte{0x17, 0x03, 0x03, 0x00, 0x05, 1, 2, 3, 4, 5}); ok {
			t.Fatal("a non-handshake record must return ok=false")
		}
	})

	t.Run("empty-and-short", func(t *testing.T) {
		for _, in := range [][]byte{nil, {}, {0x16}, {0x16, 0x03, 0x01, 0x00}} {
			if _, ok := parseClientHelloALPN(in); ok {
				t.Fatalf("short input %v must return ok=false", in)
			}
		}
	})
}

// FuzzParseClientHelloALPN asserts the parser never panics and never over-reads
// on arbitrary attacker-influenced input, and that a successful parse never
// yields an empty protocol name. This is the new-attack-surface guard the
// reviewers required.
func FuzzParseClientHelloALPN(f *testing.F) {
	f.Add(buildClientHello([]string{"h2", "http/1.1"}, true))
	f.Add(buildClientHello([]string{"http/1.1"}, true))
	f.Add(buildClientHello(nil, false))
	f.Add([]byte{0x16, 0x03, 0x01, 0x00, 0x00})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		protos, ok := parseClientHelloALPN(data)
		if ok {
			if len(protos) == 0 {
				t.Fatal("ok=true with empty protocol list")
			}
			for _, p := range protos {
				if p == "" {
					t.Fatal("ok=true with an empty protocol name")
				}
			}
		}
	})
}
