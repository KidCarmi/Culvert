package applianceconsole

import (
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestStorageCheckReserveAndInodeBoundaries(t *testing.T) {
	tests := []struct {
		name                        string
		available, total, free, all uint64
		want                        string
	}{
		{"healthy", 4 << 30, 20 << 30, 50, 100, "ok"},
		{"exact reserve", 2 << 30, 20 << 30, 5, 100, "ok"},
		{"absolute bytes low", (2 << 30) - 1, 10 << 30, 50, 100, "warning"},
		{"relative bytes low", 3 << 30, 40 << 30, 50, 100, "warning"},
		{"inodes low", 4 << 30, 20 << 30, 4, 100, "warning"},
		{"full", 0, 20 << 30, 0, 100, "warning"},
		{"no inode reporting", 4 << 30, 20 << 30, 0, 0, "unknown"},
		{"low bytes without inode reporting", 1, 20 << 30, 0, 0, "warning"},
		{"unknown filesystem size", 0, 0, 0, 0, "unknown"},
		{"inconsistent capacity", 21 << 30, 20 << 30, 50, 100, "unknown"},
		{"inconsistent inode counts", 4 << 30, 20 << 30, 101, 100, "unknown"},
		{"large counts cannot overflow", ^uint64(0) / 2, ^uint64(0), ^uint64(0) / 2, ^uint64(0), "ok"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := StorageCheck("storage:/", tt.available, tt.total, tt.free, tt.all)
			if got.State != tt.want || got.ID != "storage:/" {
				t.Fatalf("got %+v, want %s", got, tt.want)
			}
		})
	}
}

func TestConfiguredFQDNDoesNotInventDNSTarget(t *testing.T) {
	for _, raw := range []string{"", "localhost", "culvert", "192.0.2.1", "2001:db8::1", "a..b", "-host.test", "host-.test", "host.test\nother.test", "host.test\x1b", "höst.test", "https://host.test", strings.Repeat("x", 64) + ".test", strings.Repeat("abcd.", 51) + "test"} {
		if got := ConfiguredFQDN(raw); got != "" {
			t.Errorf("unexpected DNS query %q for %q", got, raw)
		}
	}
	for _, raw := range []string{"culvert.example.test", "Culvert.Example.Test.\n", "  culvert.example.test\n"} {
		if got := ConfiguredFQDN(raw); got != "culvert.example.test." {
			t.Errorf("got %q for %q", got, raw)
		}
	}
}

func TestClockCheckNeverEquatesAvailabilityWithSynchronization(t *testing.T) {
	for raw, want := range map[string]string{"yes\n": "ok", "no\n": "warning", "": "unknown", "active": "unknown", "yes\nno": "unknown", "NTPSynchronized=yes": "unknown"} {
		if got := ClockCheck(raw); got.State != want {
			t.Errorf("%q: got %+v, want %s", raw, got, want)
		}
	}
}

func TestCertificateValidityBoundariesAndPublicFingerprint(t *testing.T) {
	now := time.Date(2026, time.October, 4, 12, 0, 0, 0, time.UTC)
	for _, tt := range []struct {
		name          string
		before, after time.Time
		state, detail string
	}{
		{"valid", now.Add(-time.Hour), now.Add(40 * 24 * time.Hour), "ok", "Valid at host clock"},
		{"exact not before", now, now.Add(40 * 24 * time.Hour), "ok", "Valid at host clock"},
		{"future", now.Add(time.Second), now.Add(time.Hour), "warning", "Not yet valid"},
		{"expiry instant", now.Add(-time.Hour), now, "warning", "Expired"},
		{"expired", now.Add(-time.Hour), now.Add(-time.Second), "warning", "Expired"},
		{"expiring", now.Add(-time.Hour), now.Add(24 * time.Hour), "warning", "Expires within 30 days"},
		{"exact reserve", now.Add(-time.Hour), now.Add(30 * 24 * time.Hour), "ok", "Valid at host clock"},
		{"invalid interval", now, now, "unknown", "unavailable"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cert := &x509.Certificate{Raw: []byte("public leaf DER"), NotBefore: tt.before, NotAfter: tt.after}
			got := CertificateCheck(cert, now)
			if got.State != tt.state || !strings.Contains(got.Detail, tt.detail) {
				t.Fatalf("got %+v", got)
			}
			if got.State != "unknown" && (!strings.Contains(got.Detail, fmt.Sprintf("%x", sha256.Sum256(cert.Raw))) || !strings.Contains(got.Detail, "trust and hostname not verified")) {
				t.Fatalf("fingerprint or trust limitation missing: %+v", got)
			}
		})
	}
	for _, cert := range []*x509.Certificate{nil, {NotBefore: now, NotAfter: now.Add(time.Hour)}} {
		if got := CertificateCheck(cert, now); got.State != "unknown" {
			t.Fatalf("invented certificate evidence: %+v", got)
		}
	}
}
