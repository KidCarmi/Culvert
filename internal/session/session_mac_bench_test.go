package session

// Benchmarks behind the pooled MAC engine. Both shapes — the engine and a
// verbatim copy of the per-call hmac.New form it replaced (legacyMAC /
// legacyMacEqual in session_mac_test.go) — are measured in the SAME run so a
// slow or differently-tuned runner cannot make the comparison lie.
//
// The allocation contract these establish is enforced by
// session_mac_benchgate_test.go.

import (
	"strings"
	"testing"
	"time"
)

// benchSessionToken returns a representative cookie: the shape the proxy
// authentication path actually verifies (two groups, an email subject, a jti),
// under a deterministic 32-byte key.
func benchSessionToken(tb testing.TB) (token, payload, sig string) {
	tb.Helper()
	SetSigningKey(testKey("bench session token"))
	s := &Session{
		Sub:      "alice@example.com",
		Email:    "alice@example.com",
		Name:     "Alice Example",
		Groups:   []string{"engineering", "proxy-users"},
		Provider: "okta",
		Role:     "viewer",
		Exp:      time.Now().Add(time.Hour).Unix(),
		Jti:      "0f1e2d3c4b5a69788796a5b4c3d2e1f0",
	}
	raw, err := Encode(s)
	if err != nil {
		tb.Fatalf("Encode: %v", err)
	}
	dot := strings.LastIndex(raw, ".")
	return raw, raw[:dot], raw[dot+1:]
}

// ─── The verify step in isolation: engine vs the form it replaced ────────────

func BenchmarkMacVerify(b *testing.B) {
	_, payload, sig := benchSessionToken(b)
	b.ReportAllocs()
	for b.Loop() {
		if !macEqual(payload, sig) {
			b.Fatal("signature rejected")
		}
	}
}

func BenchmarkMacVerifyLegacy(b *testing.B) {
	_, payload, sig := benchSessionToken(b)
	b.ReportAllocs()
	for b.Loop() {
		if !legacyMacEqual(payload, sig) {
			b.Fatal("signature rejected")
		}
	}
}

func BenchmarkMacVerifyParallel(b *testing.B) {
	_, payload, sig := benchSessionToken(b)
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if !macEqual(payload, sig) {
				b.Fatal("signature rejected")
			}
		}
	})
}

func BenchmarkMacVerifyLegacyParallel(b *testing.B) {
	_, payload, sig := benchSessionToken(b)
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if !legacyMacEqual(payload, sig) {
				b.Fatal("signature rejected")
			}
		}
	})
}

// A rejected signature is the attacker-controlled shape: it must not be
// cheaper or more expensive in a way that depends on the payload, and it must
// not allocate either.
func BenchmarkMacVerifyReject(b *testing.B) {
	_, payload, sig := benchSessionToken(b)
	bad := "~" + sig[1:]
	b.ReportAllocs()
	for b.Loop() {
		if macEqual(payload, bad) {
			b.Fatal("tampered signature accepted")
		}
	}
}

// ─── mac() itself, used once per login by Encode ─────────────────────────────

func BenchmarkMac(b *testing.B) {
	_, payload, _ := benchSessionToken(b)
	b.ReportAllocs()
	for b.Loop() {
		_ = mac(payload)
	}
}

func BenchmarkMacLegacy(b *testing.B) {
	_, payload, _ := benchSessionToken(b)
	b.ReportAllocs()
	for b.Loop() {
		_ = legacyMAC(payload)
	}
}

// A payload past the inline scratch buffer takes the conversion fallback.
func BenchmarkMacOversizePayload(b *testing.B) {
	benchSessionToken(b)
	payload := strings.Repeat("x", macScratchLen+1)
	b.ReportAllocs()
	for b.Loop() {
		_ = mac(payload)
	}
}

// ─── Decode end to end: what one authenticated proxied request pays ──────────

func BenchmarkDecode(b *testing.B) {
	token, _, _ := benchSessionToken(b)
	withBenchRevocationList(b)
	b.ReportAllocs()
	for b.Loop() {
		if _, err := Decode(token); err != nil {
			b.Fatalf("Decode: %v", err)
		}
	}
}

func BenchmarkDecodeParallel(b *testing.B) {
	token, _, _ := benchSessionToken(b)
	withBenchRevocationList(b)
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := Decode(token); err != nil {
				b.Fatalf("Decode: %v", err)
			}
		}
	})
}

// BenchmarkDecodeKeyRebindPerOp is the engine's worst case: a signing-key
// CHANGE for every single verify, so every Decode pays a fresh engine and a
// cold pool. Nothing in the product does this — SetSigningKey runs at startup,
// on a GUI rotation, and on a CP snapshot apply — but it bounds the regression
// if something ever did, and it is the number the trade-off is argued from.
func BenchmarkDecodeKeyRebindPerOp(b *testing.B) {
	token, _, _ := benchSessionToken(b)
	withBenchRevocationList(b)
	issued := SigningKey()
	other := testKey("bench rebind away")
	b.ReportAllocs()
	for b.Loop() {
		SetSigningKey(other)  // rebind away …
		SetSigningKey(issued) // … and back, so the token still verifies
		if _, err := Decode(token); err != nil {
			b.Fatalf("Decode: %v", err)
		}
	}
}

// BenchmarkDecodeKeyReinstallPerOp is the shape that actually occurs: the CP
// snapshot path reinstalling the SAME secret alongside live verification.
// SetSigningKey recognises the no-op and keeps the pool warm, so this must
// stay level with BenchmarkDecode rather than with the rebind case above.
func BenchmarkDecodeKeyReinstallPerOp(b *testing.B) {
	token, _, _ := benchSessionToken(b)
	withBenchRevocationList(b)
	issued := SigningKey()
	b.ReportAllocs()
	for b.Loop() {
		SetSigningKey(issued)
		if _, err := Decode(token); err != nil {
			b.Fatalf("Decode: %v", err)
		}
	}
}

// withBenchRevocationList isolates the package revocation singleton for b, so
// a revocation left behind by another test cannot change what Decode measures.
func withBenchRevocationList(b *testing.B) {
	b.Helper()
	b.Cleanup(Revoked.SwapForTest())
}

// BenchmarkDecodeLegacyMac reconstructs the pre-change cost of one verify
// WITHOUT copying Decode's body. A verbatim copy did that, and `dupl`
// correctly objected to a 35-line clone of production logic living in a test
// — a clone that would also have to be kept in sync by hand.
//
// The reconstruction is exact where it counts: the current verify step
// allocates nothing, so `legacy MAC + current Decode` allocates precisely what
// Decode allocated before the engine — the 26 allocs/op and 1648 B/op the gate
// compares against — out of two calls instead of a clone.
//
// It is NOT a timing oracle. ns/op here also pays one extra (allocation-free)
// macEqual, so it overstates the old wall time by about that call. The gate
// keys on allocations, which this measures exactly; the timing comparison
// belongs to BenchmarkMacVerify vs BenchmarkMacVerifyLegacy, which isolate the
// step that actually changed.
func BenchmarkDecodeLegacyMac(b *testing.B) {
	token, payload, sig := benchSessionToken(b)
	withBenchRevocationList(b)
	b.ReportAllocs()
	for b.Loop() {
		if !legacyMacEqual(payload, sig) {
			b.Fatal("signature rejected")
		}
		if _, err := Decode(token); err != nil {
			b.Fatalf("Decode: %v", err)
		}
	}
}

func BenchmarkDecodeLegacyMacParallel(b *testing.B) {
	token, payload, sig := benchSessionToken(b)
	withBenchRevocationList(b)
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if !legacyMacEqual(payload, sig) {
				b.Fatal("signature rejected")
			}
			if _, err := Decode(token); err != nil {
				b.Fatalf("Decode: %v", err)
			}
		}
	})
}
