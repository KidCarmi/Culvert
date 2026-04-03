package main

// p4_test.go — Tests for P3 enterprise features: CA auto-rotation, per-rule
// metrics, byte counting, policy conflict detection, KeyProvider interface.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ── CA Auto-Rotation ─────────────────────────────────────────────────────────

func TestCAExpiry_NoCA(t *testing.T) {
	cm := &CertManager{cache: map[string]*certCacheEntry{}}
	if !cm.CAExpiry().IsZero() {
		t.Fatal("CAExpiry should return zero when CA not ready")
	}
}

func TestCAExpiry_HasCA(t *testing.T) {
	cm := &CertManager{cache: map[string]*certCacheEntry{}}
	if err := cm.InitCA(); err != nil {
		t.Fatal(err)
	}
	exp := cm.CAExpiry()
	if exp.IsZero() {
		t.Fatal("CAExpiry should return non-zero after InitCA")
	}
	if time.Until(exp) < 365*24*time.Hour {
		t.Fatal("CA should expire more than 1 year from now")
	}
}

func TestRotateIfNeeded_NotNeeded(t *testing.T) {
	cm := &CertManager{cache: map[string]*certCacheEntry{}}
	if err := cm.InitCA(); err != nil {
		t.Fatal(err)
	}
	// Fresh CA is 10 years out — should not need rotation.
	if cm.RotateIfNeeded("", "") {
		t.Fatal("fresh CA should not need rotation")
	}
}

func TestRotateIfNeeded_Needed(t *testing.T) {
	cm := &CertManager{cache: map[string]*certCacheEntry{}}
	// Create a CA that expires in 5 days (< 30 day overlap).
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Expiring CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(5 * 24 * time.Hour), // 5 days
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certDER)
	cm.mu.Lock()
	cm.caCert = cert
	cm.caKey = key
	cm.mu.Unlock()

	origExpiry := cm.CAExpiry()

	if !cm.RotateIfNeeded("", "") {
		t.Fatal("expiring CA should trigger rotation")
	}

	newExpiry := cm.CAExpiry()
	if !newExpiry.After(origExpiry) {
		t.Fatal("new CA should expire later than the old one")
	}
}

func TestRotateIfNeeded_PersistsToDisk(t *testing.T) {
	cm := &CertManager{cache: map[string]*certCacheEntry{}}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Expiring CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(2 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certDER)
	cm.mu.Lock()
	cm.caCert = cert
	cm.caKey = key
	cm.mu.Unlock()

	path := filepath.Join(t.TempDir(), "rotated.bundle")
	cm.RotateIfNeeded(path, "testpass")

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("rotated CA bundle not saved: %v", err)
	}
}

func TestRotateIfNeeded_NoCA(t *testing.T) {
	cm := &CertManager{cache: map[string]*certCacheEntry{}}
	if cm.RotateIfNeeded("", "") {
		t.Fatal("should return false with no CA")
	}
}

// ── KeyProvider Interface ────────────────────────────────────────────────────

func TestLocalKeyProvider_Implements(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p := &localKeyProvider{key: key}

	// Check interface methods.
	if p.Name() != "local" {
		t.Fatalf("Name = %q, want local", p.Name())
	}
	pub := p.PublicKey()
	if pub == nil {
		t.Fatal("PublicKey should not be nil")
	}

	// SignCertificate should produce valid DER.
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(99),
		Subject:               pkix.Name{CommonName: "test"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := p.SignCertificate(tmpl, tmpl, &key.PublicKey)
	if err != nil {
		t.Fatalf("SignCertificate: %v", err)
	}
	if len(der) == 0 {
		t.Fatal("DER output should be non-empty")
	}
}

func TestSetKeyProvider(t *testing.T) {
	cm := &CertManager{cache: map[string]*certCacheEntry{}}
	if cm.KeyProviderName() != "local" {
		t.Fatalf("default provider = %q, want local", cm.KeyProviderName())
	}

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cm.SetKeyProvider(&localKeyProvider{key: key})
	if cm.KeyProviderName() != "local" {
		t.Fatal("should still be local after setting localKeyProvider")
	}
	if cm.keyProvider == nil {
		t.Fatal("keyProvider should be set")
	}
}

// ── Per-Rule Metrics ─────────────────────────────────────────────────────────

func TestRuleMetrics_RecordHit(t *testing.T) {
	rm := &ruleMetrics{hits: make(map[string]*int64)}
	rm.RecordHit("rule-A")
	rm.RecordHit("rule-A")
	rm.RecordHit("rule-B")

	rm.mu.RLock()
	defer rm.mu.RUnlock()
	if len(rm.hits) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(rm.hits))
	}
	if got := atomic.LoadInt64(rm.hits["rule-A"]); got != 2 {
		t.Fatalf("rule-A hits = %d, want 2", got)
	}
	if got := atomic.LoadInt64(rm.hits["rule-B"]); got != 1 {
		t.Fatalf("rule-B hits = %d, want 1", got)
	}
}

func TestRuleMetrics_EmptyName(t *testing.T) {
	rm := &ruleMetrics{hits: make(map[string]*int64)}
	rm.RecordHit("")
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	if len(rm.hits) != 0 {
		t.Fatal("empty rule name should be ignored")
	}
}

func TestRuleMetrics_CardinalityCap(t *testing.T) {
	rm := &ruleMetrics{hits: make(map[string]*int64)}
	for i := 0; i < maxRuleMetrics+50; i++ {
		rm.RecordHit(big.NewInt(int64(i)).Text(36))
	}
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	if len(rm.hits) > maxRuleMetrics {
		t.Fatalf("cardinality cap breached: %d > %d", len(rm.hits), maxRuleMetrics)
	}
}

func TestRuleMetrics_WritePrometheus(t *testing.T) {
	rm := &ruleMetrics{hits: make(map[string]*int64)}
	rm.RecordHit("test-rule")
	rm.RecordHit("test-rule")

	var buf strings.Builder
	rm.WritePrometheus(&buf)
	out := buf.String()
	if !strings.Contains(out, "culvert_policy_rule_hits_total") {
		t.Fatal("output should contain metric name")
	}
	if !strings.Contains(out, "test-rule") {
		t.Fatal("output should contain rule name")
	}
}

func TestRuleMetrics_WritePrometheusEmpty(t *testing.T) {
	rm := &ruleMetrics{hits: make(map[string]*int64)}
	var buf strings.Builder
	rm.WritePrometheus(&buf)
	if buf.Len() != 0 {
		t.Fatal("empty metrics should produce no output")
	}
}

func TestRuleMetrics_ConcurrentRecordHit(t *testing.T) {
	rm := &ruleMetrics{hits: make(map[string]*int64)}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				rm.RecordHit("concurrent-rule")
			}
		}()
	}
	wg.Wait()
	rm.mu.RLock()
	got := atomic.LoadInt64(rm.hits["concurrent-rule"])
	rm.mu.RUnlock()
	if got != 2000 {
		t.Fatalf("concurrent hits = %d, want 2000", got)
	}
}

// ── Byte Counting ────────────────────────────────────────────────────────────

func TestCountingReader(t *testing.T) {
	data := "hello world"
	cr := &countingReader{r: nopReadCloser{strings.NewReader(data)}}
	buf := make([]byte, 5)
	n, _ := cr.Read(buf)
	if n != 5 || cr.count != 5 {
		t.Fatalf("first read: n=%d count=%d, want 5/5", n, cr.count)
	}
	n, _ = cr.Read(buf)
	if cr.count != int64(5+n) {
		t.Fatalf("cumulative count wrong: got %d", cr.count)
	}
	_ = cr.Close()
}

func TestRecordRequestBytes(t *testing.T) {
	// Reset counters.
	origTotal := atomic.LoadInt64(&statTotal)
	recordRequestBytes("127.0.0.1", "GET", "example.com", "OK", "", "", "", 100, 200)
	newTotal := atomic.LoadInt64(&statTotal)
	if newTotal != origTotal+1 {
		t.Fatal("recordRequestBytes should increment statTotal")
	}
}

// ── Policy Conflict Detection ────────────────────────────────────────────────

func TestDetectConflicts_NoConflict(t *testing.T) {
	ps := &PolicyStore{}
	ps.Add(PolicyRule{Name: "r1", Priority: 1, Action: ActionAllow, DestFQDN: "a.com"})
	ps.Add(PolicyRule{Name: "r2", Priority: 2, Action: ActionBlockPage, DestFQDN: "b.com"})
	conflicts := ps.DetectConflicts()
	if len(conflicts) != 0 {
		t.Fatalf("expected no conflicts, got %v", conflicts)
	}
}

func TestDetectConflicts_SamePriorityDiffAction(t *testing.T) {
	ps := &PolicyStore{}
	ps.Add(PolicyRule{Name: "r1", Priority: 1, Action: ActionAllow, DestFQDN: "*.example.com"})
	ps.Add(PolicyRule{Name: "r2", Priority: 1, Action: ActionBlockPage, DestFQDN: "*.example.com"})
	conflicts := ps.DetectConflicts()
	if len(conflicts) == 0 {
		t.Fatal("expected at least one conflict")
	}
}

// ── nopReadCloser helper ─────────────────────────────────────────────────────

type nopReadCloser struct{ *strings.Reader }

func (nopReadCloser) Close() error { return nil }
