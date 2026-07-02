package main

// bandwidth_test.go — admin-API handler tests for apiBandwidthPolicies. The
// engine tests moved to internal/bandwidth with the ADR-0002 extraction.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

func TestApiBandwidthPolicies_GET(t *testing.T) {
	origBW := globalBandwidth
	defer func() { globalBandwidth = origBW }()

	globalBandwidth = NewBandwidthManager(filepath.Join(t.TempDir(), "bw.json"))
	_, _ = globalBandwidth.Add(BandwidthPolicy{
		Name:           "api-test",
		LabelSelector:  map[string]string{"tier": "gold"},
		MaxBytesPerSec: 10 * 1024 * 1024,
		Priority:       5,
	})

	w := httptest.NewRecorder()
	r := getReq("/api/cluster/bandwidth")

	apiBandwidthPolicies(w, r)
	assertStatus(t, w, http.StatusOK)

	var infos []BandwidthPolicyInfo
	if err := json.Unmarshal(w.Body.Bytes(), &infos); err != nil {
		t.Fatalf("invalid JSON response: %v; body: %s", err, w.Body.String())
	}
	if len(infos) != 1 {
		t.Fatalf("expected 1 policy, got %d", len(infos))
	}
	if infos[0].Name != "api-test" {
		t.Fatalf("policy Name = %q, want %q", infos[0].Name, "api-test")
	}
	if infos[0].HumanRate != "10 MB/s" {
		t.Fatalf("HumanRate = %q, want %q", infos[0].HumanRate, "10 MB/s")
	}
}

func TestApiBandwidthPolicies_MethodNotAllowed(t *testing.T) {
	origBW := globalBandwidth
	defer func() { globalBandwidth = origBW }()

	globalBandwidth = NewBandwidthManager(filepath.Join(t.TempDir(), "bw.json"))

	w := httptest.NewRecorder()
	r := jsonReq(http.MethodPut, "/api/cluster/bandwidth", nil)

	apiBandwidthPolicies(w, r)
	assertStatus(t, w, http.StatusMethodNotAllowed)
}

func TestApiBandwidthPolicies_POST(t *testing.T) {
	origBW := globalBandwidth
	defer func() { globalBandwidth = origBW }()

	globalBandwidth = NewBandwidthManager(filepath.Join(t.TempDir(), "bw.json"))

	w := httptest.NewRecorder()
	r := jsonReq(http.MethodPost, "/api/cluster/bandwidth", map[string]any{
		"name":              "new-pol",
		"label_selector":    map[string]string{"region": "eu"},
		"max_bytes_per_sec": 2048,
		"priority":          3,
	})

	apiBandwidthPolicies(w, r)
	assertStatus(t, w, http.StatusOK)

	var info BandwidthPolicyInfo
	if err := json.Unmarshal(w.Body.Bytes(), &info); err != nil {
		t.Fatalf("invalid JSON response: %v", err)
	}
	if info.Name != "new-pol" {
		t.Fatalf("Name = %q, want %q", info.Name, "new-pol")
	}
}

func TestApiBandwidthPolicies_DELETE(t *testing.T) {
	origBW := globalBandwidth
	defer func() { globalBandwidth = origBW }()

	globalBandwidth = NewBandwidthManager(filepath.Join(t.TempDir(), "bw.json"))
	_, _ = globalBandwidth.Add(BandwidthPolicy{Name: "to-delete"})

	w := httptest.NewRecorder()
	r := getReq("/api/cluster/bandwidth?name=to-delete")
	r.Method = http.MethodDelete

	apiBandwidthPolicies(w, r)
	assertStatus(t, w, http.StatusOK)

	// Verify it's gone.
	if len(globalBandwidth.List()) != 0 {
		t.Fatal("policy should be deleted")
	}
}

func TestApiBandwidthPolicies_NilManager(t *testing.T) {
	origBW := globalBandwidth
	defer func() { globalBandwidth = origBW }()

	globalBandwidth = nil

	w := httptest.NewRecorder()
	r := getReq("/api/cluster/bandwidth")

	apiBandwidthPolicies(w, r)
	assertStatus(t, w, http.StatusServiceUnavailable)
}
