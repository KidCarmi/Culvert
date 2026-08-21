package secscan

import "testing"

// Scanner.Enabled() is the outermost per-request gate: proxy.go's
// preDispatchBlocked consults it before any threat check, on EVERY proxied
// request (CONNECT, plain HTTP, WebSocket). RemoteScanner.Enabled() is the same
// shape one layer down, consulted per plain-HTTP response.
//
// The parallel variants are the ones that matter. When these read a bool
// through the owning RWMutex, every core performs a read-modify-write on one
// shared reader-count word, so the gate gets SLOWER as cores are added — the
// opposite of what a read-only config probe should do. Lock-free, ns/op under
// RunParallel should fall well below the serial number.
//
// Run:
//
//	go test -run '^$' -bench 'BenchmarkScannerGate|BenchmarkRemoteScannerGate' -benchmem ./internal/secscan/

func BenchmarkScannerGate_Enabled(b *testing.B) {
	ss := New(Deps{})
	ss.Init("", 0, nil)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !ss.Enabled() {
			b.Fatal("scanner reported disabled")
		}
	}
}

func BenchmarkScannerGate_EnabledParallel(b *testing.B) {
	ss := New(Deps{})
	ss.Init("", 0, nil)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if !ss.Enabled() {
				b.Fatal("scanner reported disabled")
			}
		}
	})
}

// BenchmarkScannerGate_DisabledParallel is the default posture: no scanner
// configured, so the gate answers "no" and the whole threat-check block is
// skipped. This is the number most deployments actually pay per request.
func BenchmarkScannerGate_DisabledParallel(b *testing.B) {
	ss := New(Deps{})
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if ss.Enabled() {
				b.Fatal("scanner reported enabled")
			}
		}
	})
}

func BenchmarkRemoteScannerGate_DisabledParallel(b *testing.B) {
	rs := &RemoteScanner{}
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if rs.Enabled() {
				b.Fatal("remote scanner reported enabled")
			}
		}
	})
}
