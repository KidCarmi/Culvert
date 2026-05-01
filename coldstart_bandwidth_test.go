package main

// D1.2b cold-start tests for /data/bandwidth.json.
//
// NewBandwidthManager always returns a non-nil *BandwidthManager —
// load errors are logged and reset m.policies to nil. These tests pin
// that contract across missing / empty / garbage / valid / unknown-
// field / missing-required-field inputs.
//
// One D1.2-flag finding pinned by the missing_required_field case:
// json.Unmarshal silently fills missing fields with zero values, so a
// policy that omits Name and LabelSelector loads as a zero-name
// match-nothing policy. There is no validation in the loader; the
// admin API may validate elsewhere, but a hand-edited file bypasses
// that check.

import (
	"os"
	"path/filepath"
	"testing"
)

//nolint:funlen,dupl // Table-driven case list is intentionally long; cross-file
// duplication with coldstart_nodegroups_test.go is by design — the two artifacts
// have structurally identical loaders and the symmetry is part of the regression
// guard. Refactoring to a shared helper would obscure per-artifact assertions.
func TestColdStart_Bandwidth_Cases(t *testing.T) {
	cases := []struct {
		name         string
		body         []byte // nil = do not write the file
		wantPolicies int
		verify       func(t *testing.T, m *BandwidthManager)
	}{
		{
			name:         "missing_file",
			body:         nil,
			wantPolicies: 0,
		},
		{
			name:         "empty_file",
			body:         []byte{},
			wantPolicies: 0,
		},
		{
			name:         "empty_array",
			body:         []byte("[]"),
			wantPolicies: 0,
		},
		{
			name: "empty_object",
			// `{}` cannot unmarshal into []BandwidthPolicy → log + nil.
			body:         []byte("{}"),
			wantPolicies: 0,
		},
		{
			name:         "garbage_json",
			body:         []byte("not json at all"),
			wantPolicies: 0,
		},
		{
			name:         "valid_one_policy",
			body:         []byte(`[{"name":"p1","label_selector":{"role":"edge"},"max_bytes_per_sec":1024,"priority":1}]`),
			wantPolicies: 1,
			verify: func(t *testing.T, m *BandwidthManager) {
				p := m.policies[0]
				if p.Name != "p1" {
					t.Errorf("Name = %q, want p1", p.Name)
				}
				if p.MaxBytesPerSec != 1024 {
					t.Errorf("MaxBytesPerSec = %d, want 1024", p.MaxBytesPerSec)
				}
			},
		},
		{
			name:         "valid_with_unknown_field",
			body:         []byte(`[{"name":"p2","label_selector":{},"max_bytes_per_sec":2048,"future_field":"ignored"}]`),
			wantPolicies: 1,
			verify: func(t *testing.T, m *BandwidthManager) {
				if m.policies[0].MaxBytesPerSec != 2048 {
					t.Errorf("MaxBytesPerSec = %d, want 2048", m.policies[0].MaxBytesPerSec)
				}
			},
		},
		{
			// D1.2-flag: missing required fields silently load as zero
			// values. A policy with no Name and no LabelSelector still
			// loads — it just matches nothing at runtime.
			name:         "missing_required_fields",
			body:         []byte(`[{"max_bytes_per_sec":4096}]`),
			wantPolicies: 1,
			verify: func(t *testing.T, m *BandwidthManager) {
				p := m.policies[0]
				if p.Name != "" {
					t.Errorf("Name should be zero value, got %q", p.Name)
				}
				if len(p.LabelSelector) != 0 {
					t.Errorf("LabelSelector should be empty, got %v", p.LabelSelector)
				}
				if p.MaxBytesPerSec != 4096 {
					t.Errorf("MaxBytesPerSec = %d, want 4096", p.MaxBytesPerSec)
				}
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "bandwidth.json")
			if tc.body != nil {
				if err := os.WriteFile(path, tc.body, 0o600); err != nil {
					t.Fatalf("write: %v", err)
				}
			}

			m := NewBandwidthManager(path)
			if m == nil {
				t.Fatal("NewBandwidthManager returned nil — contract is always non-nil")
			}
			if got := len(m.policies); got != tc.wantPolicies {
				t.Errorf("policies len = %d, want %d", got, tc.wantPolicies)
			}
			if tc.verify != nil {
				tc.verify(t, m)
			}
		})
	}
}
