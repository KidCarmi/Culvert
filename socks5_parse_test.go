package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"testing"
)

// socks5Frame builds a SOCKS5 request wire frame: VER CMD RSV ATYP <addr> PORT.
// addr is the raw ATYP-specific address bytes (for a domain, a length byte
// followed by the name); pass nil to omit (used for unsupported-ATYP frames
// where the parser returns before reading an address).
func socks5Frame(ver, cmd, rsv, atyp byte, addr []byte, port uint16) []byte {
	b := []byte{ver, cmd, rsv, atyp}
	b = append(b, addr...)
	p := make([]byte, 2)
	binary.BigEndian.PutUint16(p, port)
	return append(b, p...)
}

func domainAddr(name string) []byte {
	return append([]byte{byte(len(name))}, []byte(name)...)
}

// errKind classifies the expected error without pinning an exact value for the
// generic-error rows (io.ErrUnexpectedEOF etc.).
type errKind int

const (
	errNone  errKind = iota // err == nil
	errATYP                 // errors.Is(err, errSOCKS5ATYPUnsupported)
	errOther                // err != nil AND NOT the ATYP sentinel
)

func TestParseSOCKS5Request(t *testing.T) {
	ipv6 := net.ParseIP("2001:db8::1").To16()

	tests := []struct {
		name     string
		in       []byte
		wantCmd  byte
		wantHost string
		wantPort uint16
		wantErr  errKind
	}{
		{
			name:    "IPv4 CONNECT",
			in:      socks5Frame(0x05, 0x01, 0x00, 0x01, []byte{93, 184, 216, 34}, 443),
			wantCmd: 0x01, wantHost: "93.184.216.34", wantPort: 443, wantErr: errNone,
		},
		{
			name:    "IPv6 CONNECT is bracketed",
			in:      socks5Frame(0x05, 0x01, 0x00, 0x04, ipv6, 8080),
			wantCmd: 0x01, wantHost: "[2001:db8::1]", wantPort: 8080, wantErr: errNone,
		},
		{
			name:    "domain CONNECT",
			in:      socks5Frame(0x05, 0x01, 0x00, 0x03, domainAddr("example.com"), 80),
			wantCmd: 0x01, wantHost: "example.com", wantPort: 80, wantErr: errNone,
		},
		{
			// Behavior contract: a zero-length domain is ACCEPTED (host=="",
			// err==nil), matching the prior inline parser; the SSRF guard rejects
			// it downstream. The fuzz target relies on this being a valid parse.
			name:    "empty domain is accepted with empty host",
			in:      socks5Frame(0x05, 0x01, 0x00, 0x03, []byte{0x00}, 80),
			wantCmd: 0x01, wantHost: "", wantPort: 80, wantErr: errNone,
		},
		{
			name:    "BIND command still parses (caller enforces CONNECT-only)",
			in:      socks5Frame(0x05, 0x02, 0x00, 0x01, []byte{10, 0, 0, 1}, 22),
			wantCmd: 0x02, wantHost: "10.0.0.1", wantPort: 22, wantErr: errNone,
		},
		{
			name:    "unsupported ATYP → sentinel (caller replies 0x08)",
			in:      []byte{0x05, 0x01, 0x00, 0x02}, // parser returns before reading addr
			wantErr: errATYP,
		},
		{
			name:    "bad version → distinct error (caller stays silent)",
			in:      []byte{0x06, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0, 80},
			wantErr: errOther,
		},
		{
			name:    "truncated header",
			in:      []byte{0x05, 0x01, 0x00},
			wantErr: errOther,
		},
		{
			name:    "truncated IPv4 address",
			in:      []byte{0x05, 0x01, 0x00, 0x01, 1, 2},
			wantErr: errOther,
		},
		{
			name:    "missing port",
			in:      []byte{0x05, 0x01, 0x00, 0x01, 1, 2, 3, 4},
			wantErr: errOther,
		},
		{
			name:    "domain length exceeds available bytes",
			in:      []byte{0x05, 0x01, 0x00, 0x03, 0xFF, 'a', 'b'},
			wantErr: errOther,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cmd, host, port, err := parseSOCKS5Request(bytes.NewReader(tc.in))

			switch tc.wantErr {
			case errNone:
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if cmd != tc.wantCmd || host != tc.wantHost || port != tc.wantPort {
					t.Fatalf("got (cmd=0x%02x host=%q port=%d), want (0x%02x %q %d)",
						cmd, host, port, tc.wantCmd, tc.wantHost, tc.wantPort)
				}
			case errATYP:
				if !errors.Is(err, errSOCKS5ATYPUnsupported) {
					t.Fatalf("want errSOCKS5ATYPUnsupported, got %v", err)
				}
			case errOther:
				if err == nil {
					t.Fatal("want a parse error, got nil")
				}
				if errors.Is(err, errSOCKS5ATYPUnsupported) {
					t.Fatalf("must NOT be the ATYP sentinel (caller would wrongly reply 0x08): %v", err)
				}
			}
		})
	}
}

// FuzzParseSOCKS5Request fuzzes the extracted SOCKS5 request wire parser — the
// attacker-controlled state machine (ATYP dispatch, length-prefixed domain read,
// address decode) that any SOCKS5 client can drive. The invariant is NO-PANIC
// ONLY: return values are intentionally unconstrained because a zero-length
// domain (ATYP=0x03, len=0) is a valid parse yielding host=="" with err==nil
// (rejected later by the SSRF guard), so any "host != ” when err == nil"
// assertion would fire on a non-bug.
func FuzzParseSOCKS5Request(f *testing.F) {
	seeds := [][]byte{
		socks5Frame(0x05, 0x01, 0x00, 0x01, []byte{93, 184, 216, 34}, 443),         // IPv4
		socks5Frame(0x05, 0x01, 0x00, 0x04, net.ParseIP("2001:db8::1").To16(), 80), // IPv6
		socks5Frame(0x05, 0x01, 0x00, 0x03, domainAddr("example.com"), 80),         // domain
		socks5Frame(0x05, 0x01, 0x00, 0x03, []byte{0x00}, 80),                      // empty domain (accepted)
		{0x05, 0x01, 0x00, 0x02, 0x00, 0x50},                                       // unsupported ATYP
		{0x06, 0x01, 0x00, 0x01},                                                   // bad version
		{0x05, 0x03, 0x00, 0x03, 0xFF, 'a'},                                        // domain len overruns
		{},                                                                         // empty
		{0x05},                                                                     // truncated
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _, _ = parseSOCKS5Request(bytes.NewReader(data)) // must not panic
	})
}
