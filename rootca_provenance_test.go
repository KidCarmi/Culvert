package main

// rootca_provenance_test.go — main's wiring of the inspection-CA provenance
// contract (internal/ca/provenance.go): the startup classification of a
// record-less bundle, the truthful autoRotation status field, and the operator
// message when renewal is withheld. The trust behaviour itself is tested beside
// its owner in internal/ca/provenance_test.go.

import (
	"bytes"
	"encoding/pem"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/ca"
)

// writeRecordlessBundle writes a bundle as builds before provenance tracking
// wrote it: certificate and key blocks only.
func writeRecordlessBundle(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ca.bundle")
	writeGoodBundle(t, path)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out []byte
	for {
		var b *pem.Block
		b, data = pem.Decode(data)
		if b == nil {
			break
		}
		if b.Type == "CERTIFICATE" || b.Type == "EC PRIVATE KEY" {
			out = append(out, pem.EncodeToMemory(b)...)
		}
	}
	if err := os.WriteFile(path, out, 0o600); err != nil { // #nosec G703 -- path is under t.TempDir()
		t.Fatal(err)
	}
	return path
}

func captureAppLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	prev := logger
	var buf bytes.Buffer
	logger = log.New(&buf, "", 0)
	t.Cleanup(func() { logger = prev })
	return &buf
}

func TestCAProvenance_StartupClassification(t *testing.T) {
	for _, tc := range []struct {
		name, env string
		want      ca.Provenance
		autoRenew bool
	}{
		{"unclassified legacy bundle is not renewed", "", ca.ProvenanceUnknown, false},
		{"unrecognised value fails toward not renewing", "yes-please", ca.ProvenanceUnknown, false},
		{"classified managed", "culvert-managed", ca.ProvenanceManaged, true},
		{"classified imported", "imported", ca.ProvenanceImported, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			swapInspectionCA(t)
			logs := captureAppLog(t)
			initInspectionCAWithProvenance(rootCAStartupConfig{Path: writeRecordlessBundle(t), LegacyProvenance: tc.env})
			if !certMgr.Ready() {
				t.Fatalf("CA did not load: %s", logs)
			}
			if got := certMgr.Provenance(); got != tc.want {
				t.Errorf("provenance = %q, want %q", got, tc.want)
			}
			if got := caAutoRenewed(); got != tc.autoRenew {
				t.Errorf("autoRotation = %v, want %v", got, tc.autoRenew)
			}
			if warned := strings.Contains(logs.String(), "will NOT be renewed automatically"); warned != (tc.want == ca.ProvenanceUnknown) {
				t.Errorf("unknown-provenance startup warning present = %v; log: %s", warned, logs)
			}
		})
	}
}

// A bundle that already carries a record is not reclassified by the env value.
func TestCAProvenance_StartupClassificationNeverOverridesARecord(t *testing.T) {
	swapInspectionCA(t)
	captureAppLog(t)
	path := filepath.Join(t.TempDir(), "ca.bundle")
	writeGoodBundle(t, path) // Culvert-generated: recorded as managed
	initInspectionCAWithProvenance(rootCAStartupConfig{Path: path, LegacyProvenance: "imported"})
	if got := certMgr.Provenance(); got != ca.ProvenanceManaged {
		t.Errorf("provenance = %q, want culvert-managed (the record wins)", got)
	}
}

func TestCAProvenance_WithheldRenewalMessageIsActionable(t *testing.T) {
	logs := captureAppLog(t)
	expiry := time.Date(2030, 1, 2, 0, 0, 0, 0, time.UTC)

	noteCARenewalWithheld(ca.ProvenanceImported, expiry)
	got := logs.String()
	for _, want := range []string{"2030-01-02", "NOT renewed automatically", "issuing PKI", "refused, not bypassed"} {
		if !strings.Contains(got, want) {
			t.Errorf("imported message lacks %q: %s", want, got)
		}
	}

	logs.Reset()
	noteCARenewalWithheld(ca.ProvenanceUnknown, expiry)
	got = logs.String()
	for _, want := range []string{"provenance: unknown", caProvenanceEnv + "=culvert-managed", "=imported"} {
		if !strings.Contains(got, want) {
			t.Errorf("unknown message lacks %q: %s", want, got)
		}
	}
}
