package main

// Tests for the automatic re-dial of an enrolled Sluice instance that a pool
// build had to skip (cdr_pool_reconcile.go).

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const redialTestPin = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

// withRedialGate resets the poller-side backoff and makes every pass
// eligible (zero delay) unless a test overrides cdrRedialDelay.
func withRedialGate(t *testing.T) {
	t.Helper()
	prev := cdrRedialDelay
	reset := func() {
		cdrRedialGate.mu.Lock()
		cdrRedialGate.failed = 0
		cdrRedialGate.nextAt = time.Time{}
		cdrRedialGate.mu.Unlock()
	}
	reset()
	cdrRedialDelay = func(int) time.Duration { return 0 }
	t.Cleanup(func() { cdrRedialDelay = prev; reset() })
}

// redialBundlePaths returns the credential paths for an instance under dir.
// Nothing is written: the caller decides when the bundle becomes readable.
func redialBundlePaths(dir string) (ca, cert, key string) {
	return filepath.Join(dir, "ca.pem"), filepath.Join(dir, "client.pem"), filepath.Join(dir, "client.key")
}

// writeRedialBundle writes a real, loadable mTLS bundle into dir.
func writeRedialBundle(t *testing.T, dir string) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "cdr-redial-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	kd, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd})
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	ca, cert, key := redialBundlePaths(dir)
	for p, b := range map[string][]byte{ca: certPEM, cert: certPEM, key: keyPEM} {
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// enrollRedialInstance registers an instance whose bundle lives in dir.
func enrollRedialInstance(t *testing.T, name, dir string, enabled bool) {
	t.Helper()
	ca, cert, key := redialBundlePaths(dir)
	en := enabled
	if _, err := cdrInstances.Add(CDREnrolledInstance{
		Name: name, Endpoint: "127.0.0.1:1", ServerFingerprint: redialTestPin,
		CACertPath: ca, ClientCertPath: cert, ClientKeyPath: key, Enabled: &en,
	}); err != nil {
		t.Fatal(err)
	}
}

// redialClosedCfg is a non-default, fail-closed config: the fields a runtime
// disable/enable would have zeroed, so the tests can prove they survive.
func redialClosedCfg() CDRConfig {
	return CDRConfig{
		Enabled: true, FailMode: "closed", DefaultProfile: "strict",
		DefaultMode: "ENFORCE", TimeoutSec: 17, MaxFileSizeMB: 33,
	}
}

func redialPoolNames() []string {
	var out []string
	for _, pc := range cdrPool.List() {
		out = append(out, pc.Name)
	}
	return out
}

func redialAuditCount(object string) int {
	n := 0
	entries := auditGet()
	for i := range entries {
		if entries[i].Action == "cdr.pool.auto_redial" && entries[i].Object == object {
			if entries[i].Actor != "system" {
				return -1
			}
			n++
		}
	}
	return n
}

// TestCDRRedial_BundleUnreadableAtBootRecoversWithoutRestart is the
// reproduction and the fix: the bundle is unreadable when the pool is built
// at boot, so the pool stays empty (fail-closed refuses every document). Once
// the bundle becomes readable, the health-poller round dials the instance in
// with the operator's fail_mode and every other cdr.* setting intact.
func TestCDRRedial_BundleUnreadableAtBootRecoversWithoutRestart(t *testing.T) {
	resetCDRState(t)
	withRedialGate(t)
	name := "redial-boot-" + strings.ReplaceAll(time.Now().Format("150405.000000"), ".", "")
	dir := filepath.Join(t.TempDir(), "not-mounted-yet")
	enrollRedialInstance(t, name, dir, true)

	cfg := redialClosedCfg()
	if err := initCDRClient(cfg); err == nil {
		t.Fatal("setup: boot pool build succeeded with an unreadable bundle")
	}
	if cdrPool.Len() != 0 || !cdrActiveConfig().Enabled {
		t.Fatalf("setup: want enabled config over an empty pool, got pool=%v enabled=%v", redialPoolNames(), cdrActiveConfig().Enabled)
	}

	// Still unreadable: the round tries, fails, and changes nothing.
	probeCDRHealth(context.Background())
	if cdrPool.Len() != 0 {
		t.Fatalf("pool gained %v while the bundle was still unreadable", redialPoolNames())
	}
	if checkCDR().Status != diagFail {
		t.Fatalf("cdr row = %q, want fail while no instance is dialled", checkCDR().Status)
	}

	// The operator mounts the volume / fixes ownership. No restart.
	writeRedialBundle(t, dir)
	probeCDRHealth(context.Background())

	if got := redialPoolNames(); len(got) != 1 || got[0] != name {
		t.Fatalf("pool = %v, want [%s] after the bundle became readable", got, name)
	}
	if got := cdrActiveConfig(); got != cfg {
		t.Fatalf("active config changed by the re-dial:\n got %+v\nwant %+v", got, cfg)
	}
	if n := redialAuditCount(name); n != 1 {
		t.Fatalf("auto_redial audit entries for %q = %d, want exactly 1 attributed to system", name, n)
	}

	// Nothing missing any more: further rounds are no-ops.
	maybeRedialMissingCDRMembers(context.Background())
	maybeRedialMissingCDRMembers(context.Background())
	if got := redialPoolNames(); len(got) != 1 {
		t.Fatalf("pool = %v after repeat rounds, want the single member once", got)
	}
	if n := redialAuditCount(name); n != 1 {
		t.Fatalf("repeat rounds re-audited: %d entries", n)
	}
}

// TestCDRRedial_PartialPoolKeepsLiveMembersUntouched: one member is serving,
// another was skipped. The re-dial appends the skipped one and leaves the
// live member's client and breaker exactly as they were.
func TestCDRRedial_PartialPoolKeepsLiveMembersUntouched(t *testing.T) {
	resetCDRState(t)
	withRedialGate(t)
	liveDir := filepath.Join(t.TempDir(), "live")
	writeRedialBundle(t, liveDir)
	enrollRedialInstance(t, "live", liveDir, true)
	skippedDir := filepath.Join(t.TempDir(), "skipped")
	enrollRedialInstance(t, "skipped", skippedDir, true)

	if err := initCDRClient(redialClosedCfg()); err != nil {
		t.Fatalf("setup: partial build should publish the live member: %v", err)
	}
	before := cdrPool.Get("live")
	if before == nil || cdrPool.Len() != 1 {
		t.Fatalf("setup: pool = %v, want [live]", redialPoolNames())
	}
	before.Breaker.OnFailure(cdrProbeReservation{}) // state that a rebuild-from-scratch would not preserve on a new client
	failsBefore := before.Breaker.Stats().ConsecFails

	writeRedialBundle(t, skippedDir)
	maybeRedialMissingCDRMembers(context.Background())

	if got := redialPoolNames(); len(got) != 2 || got[0] != "live" || got[1] != "skipped" {
		t.Fatalf("pool = %v, want [live skipped]", got)
	}
	after := cdrPool.Get("live")
	if after != before || after.Client != before.Client {
		t.Fatal("the live member was rebuilt; the re-dial must only append")
	}
	if after.Client.conn.GetState().String() == "SHUTDOWN" {
		t.Fatal("the live member's connection was closed by the re-dial")
	}
	if after.Breaker.Stats().ConsecFails != failsBefore {
		t.Fatal("the live member's breaker state was reset")
	}
}

// TestCDRRedial_RefusesOutsideItsAuthority: the negative controls. A readable
// bundle is never dialled when CDR is disabled, the instance is disabled, the
// lifecycle is cancelled, or the shutdown hook has run.
func TestCDRRedial_RefusesOutsideItsAuthority(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T) context.Context
	}{
		{"cdr disabled", func(t *testing.T) context.Context {
			cdrClientMu.Lock()
			cdrActiveCfg = CDRConfig{Enabled: false, FailMode: "closed"}
			cdrClientMu.Unlock()
			return context.Background()
		}},
		{"instance disabled", func(t *testing.T) context.Context {
			cdrInstances = &CDRInstanceRegistry{}
			dir := filepath.Join(t.TempDir(), "off")
			writeRedialBundle(t, dir)
			enrollRedialInstance(t, "off", dir, false)
			return context.Background()
		}},
		{"lifecycle cancelled", func(t *testing.T) context.Context {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			return ctx
		}},
		{"after shutdown hook", func(t *testing.T) context.Context {
			shutdownCDRClient()
			return context.Background()
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resetCDRState(t)
			withRedialGate(t)
			dir := filepath.Join(t.TempDir(), "x")
			enrollRedialInstance(t, "x", dir, true)
			_ = initCDRClient(redialClosedCfg()) // boot: bundle unreadable → empty pool
			writeRedialBundle(t, dir)            // now readable
			ctx := tc.setup(t)

			res := reconcileCDRPool(ctx)
			maybeRedialMissingCDRMembers(ctx)

			if res.attempted || cdrPool.Len() != 0 {
				t.Fatalf("re-dial acted: attempted=%v pool=%v", res.attempted, redialPoolNames())
			}
		})
	}
}

// TestCDRRedial_BackoffGatesAttempts: after a failed pass, the next pass
// waits out the delay even if the bundle became readable meanwhile.
func TestCDRRedial_BackoffGatesAttempts(t *testing.T) {
	resetCDRState(t)
	withRedialGate(t)
	cdrRedialDelay = func(int) time.Duration { return time.Hour }
	dir := filepath.Join(t.TempDir(), "gated")
	enrollRedialInstance(t, "gated", dir, true)
	_ = initCDRClient(redialClosedCfg())

	maybeRedialMissingCDRMembers(context.Background()) // fails, arms 1h
	writeRedialBundle(t, dir)
	maybeRedialMissingCDRMembers(context.Background()) // inside the window
	if cdrPool.Len() != 0 {
		t.Fatal("a pass ran inside the backoff window")
	}
	cdrRedialGate.mu.Lock()
	failed := cdrRedialGate.failed
	cdrRedialGate.nextAt = time.Time{}
	cdrRedialGate.mu.Unlock()
	if failed != 1 {
		t.Fatalf("failed attempts = %d, want 1", failed)
	}
	maybeRedialMissingCDRMembers(context.Background())
	if cdrPool.Len() != 1 {
		t.Fatalf("pool = %v after the window, want the member", redialPoolNames())
	}
	cdrRedialGate.mu.Lock()
	defer cdrRedialGate.mu.Unlock()
	if cdrRedialGate.failed != 0 || !cdrRedialGate.nextAt.IsZero() {
		t.Fatalf("gate not reset after recovery: failed=%d nextAt=%v", cdrRedialGate.failed, cdrRedialGate.nextAt)
	}
}

// TestCDRRedial_ConcurrentPassesPublishOnce: duplicate triggers never put the
// same instance in the pool twice.
func TestCDRRedial_ConcurrentPassesPublishOnce(t *testing.T) {
	resetCDRState(t)
	withRedialGate(t)
	dir := filepath.Join(t.TempDir(), "dup")
	enrollRedialInstance(t, "dup", dir, true)
	_ = initCDRClient(redialClosedCfg())
	writeRedialBundle(t, dir)

	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _ = reconcileCDRPool(context.Background()) }()
	}
	wg.Wait()
	if got := redialPoolNames(); len(got) != 1 || got[0] != "dup" {
		t.Fatalf("pool = %v, want [dup] exactly once", got)
	}
}

// TestCDRRedial_RacingAdminDisableEndsDisabled: an admin disable (flip the
// active config, then tear the pool down — the toggle's order) racing a
// re-dial always ends with no pool, whatever the interleaving.
func TestCDRRedial_RacingAdminDisableEndsDisabled(t *testing.T) {
	for i := 0; i < 50; i++ {
		resetCDRState(t)
		withRedialGate(t)
		dir := filepath.Join(t.TempDir(), "race")
		enrollRedialInstance(t, "race", dir, true)
		_ = initCDRClient(redialClosedCfg())
		writeRedialBundle(t, dir)

		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); _ = reconcileCDRPool(context.Background()) }()
		go func() {
			defer wg.Done()
			cdrClientMu.Lock()
			cdrActiveCfg.Enabled = false
			cdrClientMu.Unlock()
			shutdownCDRClient()
		}()
		wg.Wait()
		if cdrPool.Len() != 0 || cdrActiveConfig().Enabled {
			t.Fatalf("iteration %d: disable lost the race — pool=%v enabled=%v", i, redialPoolNames(), cdrActiveConfig().Enabled)
		}
	}
}

// TestCDRRedial_DropsMembersNoLongerEnrolledAsDialled: the pre/post-publish
// re-validation withdraws a member whose registry entry was removed or
// re-pointed after it was dialled.
func TestCDRRedial_DropsMembersNoLongerEnrolledAsDialled(t *testing.T) {
	resetCDRState(t)
	dir := filepath.Join(t.TempDir(), "v")
	writeRedialBundle(t, dir)
	enrollRedialInstance(t, "kept", dir, true)
	enrollRedialInstance(t, "removed", dir, true)
	cdrClientMu.Lock()
	cdrActiveCfg = redialClosedCfg()
	cdrClientMu.Unlock()

	targets := cdrInstances.SnapshotView()
	var dialed []*cdrPooledClient
	for i := range targets {
		pc, err := dialEnrolledInstance(targets[i], redialClosedCfg(), nil)
		if err != nil {
			t.Fatal(err)
		}
		dialed = append(dialed, pc)
	}
	if _, err := cdrInstances.RemoveByName("removed"); err != nil {
		t.Fatal(err)
	}
	kept, dropped := dropInvalidRedialed(context.Background(), dialed, targets, false)
	if len(kept) != 1 || kept[0].Name != "kept" || len(dropped) != 1 || dropped[0] != "removed" {
		t.Fatalf("kept=%d dropped=%v, want [kept] / [removed]", len(kept), dropped)
	}
	if dialed[1].Client.conn.GetState().String() != "SHUTDOWN" {
		t.Fatal("a dropped member's client was not closed")
	}
	_ = kept[0].Client.Close()
}

// TestCDRRedial_BootstrapCertsDirRecovers: the empty-registry bootstrap
// client is re-dialled once its certs dir becomes readable — and never
// attempted without a certs dir, where a retry cannot change the outcome.
func TestCDRRedial_BootstrapCertsDirRecovers(t *testing.T) {
	resetCDRState(t)
	withRedialGate(t)
	certs := filepath.Join(t.TempDir(), "certs")
	cfg := redialClosedCfg()
	cfg.Endpoint, cfg.ServerFingerprint, cfg.CertsDir = "127.0.0.1:1", redialTestPin, certs
	if err := initCDRClient(cfg); err == nil {
		t.Fatal("setup: bootstrap succeeded with no certs on disk")
	}
	writeRedialBundle(t, certs)
	maybeRedialMissingCDRMembers(context.Background())
	if got := redialPoolNames(); len(got) != 1 || got[0] != "default" {
		t.Fatalf("pool = %v, want [default]", got)
	}

	if _, boot := cdrMissingPoolMembers(CDRConfig{Enabled: true, Endpoint: "e", ServerFingerprint: redialTestPin}, nil); boot {
		t.Fatal("bootstrap without a certs dir would be retried")
	}
}
