package hostpin

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
)

// verdictInners and verdictTunnels span every branch of the predicate: empty
// and malformed authorities, ports the wire refuses, bracket shapes, IDNA case,
// IP literals on either side, and plain different destinations. The table is
// their full cross product.
var verdictInners = []string{
	"", "a.example.com", "A.Example.COM", "a.example.com.", "A.Example.Com.",
	"a.example.com:443", "a.example.com:8443", "a.example.com:", "a.example.com.:443",
	"a.example.com:0/x", "a.example.com:443?x", "a.example.com:@b.example.com",
	"a.example.com:443#f", "a.example.com:44 3", "a.example.com:443\\x",
	"a.example.com:{}", "a.example.com:443|x", "a.example.com:443<x", "a.example.com:443\"x",
	"[a.example.com]", "[a.example.com]:443", "a.example.com]", "[a.example.com",
	"[[2001:db8::1]]", "[2001:db8::1]", "[2001:db8::1]:443", "2001:db8::1", "[2001:db8::1",
	"[::ffff:203.0.113.5]", "203.0.113.5", "203.0.113.5:443", "203.0.113.5:0/x", "[203.0.113.5]",
	"bücher.example.com", "BÜCHER.example.com", "Bücher.example.com",
	"xn--bcher-kva.example.com", "XN--BCHER-KVA.example.com", "xn--BCHER-2pa.example.com",
	"b.example.com", "evil.a.example.com", "a.example.com.evil.test", "example.com",
	"a example.com", "a.example.com\x00", "a.example.com@b", "user@a.example.com",
	"\xff\xfe", "xn--", "xn--a.example.com", "*.example.com", "a..example.com",
	"-a.example.com", ".", "..", ":", ":443", "a.example.com/", "a.example.com\t",
	" a.example.com", "a.example.com ", "a_b.example.com", "localhost", "LOCALHOST.",
	strings.Repeat("a", 64) + ".example.com", strings.Repeat("a.", 130) + "com",
}

var verdictTunnels = []string{
	"", "a.example.com", "a.example.com:443", "A.EXAMPLE.com.", "a.example.com.",
	"xn--bcher-kva.example.com", "bücher.example.com", "BÜCHER.example.com",
	"203.0.113.5", "203.0.113.5:443", "2001:db8::1", "[2001:db8::1]:443", "[2001:db8::1]",
	"evil.a.example.com", "example.com", "localhost", "xn--", "a..example.com",
	"[a.example.com]", "a.example.com:0/x", "a_b.example.com",
}

// Captured from the root predicate (innerHostPinnedToTunnel) at main 0fe457878,
// before the move, by running verdictTable over that function. A change to any
// verdict in the table changes the digest; verdictPinnedCount keeps the table
// from being satisfied by a predicate that refuses everything.
const (
	verdictDigest      = "edab7226f0a700db2801a56ba9f3faae50d88ce7eccb2a91e9c4897852b767fa"
	verdictPinnedCount = 261
)

func verdictTable(pinned func(inner, tunnel string) bool) (digest string, accepted, total int) {
	h := sha256.New()
	for _, tunnel := range verdictTunnels {
		for _, inner := range verdictInners {
			got := pinned(inner, tunnel)
			if got {
				accepted++
			}
			total++
			fmt.Fprintf(h, "%q\t%q\t%t\n", inner, tunnel, got)
		}
	}
	return hex.EncodeToString(h.Sum(nil)), accepted, total
}

// TestPinned_VerdictTableMatchesThePreMoveCapture is the move's behavior pin:
// every verdict over the cross product equals what package main's predicate
// returned before it was relocated.
func TestPinned_VerdictTableMatchesThePreMoveCapture(t *testing.T) {
	digest, accepted, total := verdictTable(Pinned)
	if want := len(verdictInners) * len(verdictTunnels); total != want {
		t.Fatalf("table has %d rows, want %d", total, want)
	}
	if accepted != verdictPinnedCount {
		t.Errorf("pinned %d of %d pairs, want %d", accepted, total, verdictPinnedCount)
	}
	if digest != verdictDigest {
		t.Errorf("verdict digest = %s, want %s: a refusal rule changed", digest, verdictDigest)
	}
}

// TestPinned_VerdictTableDetectsARuleChange is the negative control for the
// digest: each mutant differs from Pinned on at least one row, so the table
// must tell them apart.
func TestPinned_VerdictTableDetectsARuleChange(t *testing.T) {
	mutants := map[string]func(inner, tunnel string) bool{
		"accepts an empty inner host": func(inner, tunnel string) bool {
			return inner == "" && tunnel != "" || Pinned(inner, tunnel)
		},
		"skips the bracket rule": func(inner, tunnel string) bool {
			return Pinned(strings.Trim(inner, "[]"), tunnel)
		},
		"lowercases before comparing": func(inner, tunnel string) bool {
			return Pinned(strings.ToLower(inner), tunnel)
		},
		"matches a subdomain": func(inner, tunnel string) bool {
			return Pinned(strings.TrimPrefix(inner, "evil."), tunnel)
		},
		"refuses an address tunnel": func(inner, tunnel string) bool {
			return !strings.HasPrefix(tunnel, "203.") && Pinned(inner, tunnel)
		},
	}
	for name, mutant := range mutants {
		t.Run(name, func(t *testing.T) {
			if digest, _, _ := verdictTable(mutant); digest == verdictDigest {
				t.Fatal("the verdict table did not notice this rule change")
			}
		})
	}
}
