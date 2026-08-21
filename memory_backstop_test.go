package main

// memory_backstop_test.go — P0-2 coverage for the GOMEMLIMIT backstop parsing.
// The soft limit must be set only for a real, finite container memory cap;
// "max"/unlimited/garbage must NOT produce a bogus limit that throttles a
// legitimate deployment.

import (
	"strings"
	"testing"
)

// withCachedMemoryBackstopState saves and restores memoryBackstopState so a
// test can drive the cache without leaking into neighbours. Mirrors
// withCachedStorageState (diagnostics_test.go).
func withCachedMemoryBackstopState(t *testing.T) {
	t.Helper()
	prev := memoryBackstopState.Load()
	t.Cleanup(func() {
		if prev == nil {
			memoryBackstopState.Store(memoryBackstopStatus{})
		} else {
			memoryBackstopState.Store(prev)
		}
	})
}

func TestParseCgroupMemLimit(t *testing.T) {
	const gib = int64(1) << 30
	cases := []struct {
		raw     string
		want    int64
		wantOK  bool
		comment string
	}{
		{"1073741824\n", gib, true, "cgroup v2 finite limit (1 GiB)"},
		{"  536870912  ", gib / 2, true, "whitespace-trimmed 512 MiB"},
		{"max", 0, false, "cgroup v2 unlimited literal"},
		{"", 0, false, "empty file"},
		{"9223372036854771712", 0, false, "cgroup v1 unlimited sentinel (~max int64)"},
		{"0", 0, false, "zero is not a real cap"},
		{"-1", 0, false, "negative is not a real cap"},
		{"not-a-number", 0, false, "garbage"},
	}
	for _, c := range cases {
		got, ok := parseCgroupMemLimit(c.raw)
		if ok != c.wantOK || (ok && got != c.want) {
			t.Errorf("parseCgroupMemLimit(%q) = (%d,%v), want (%d,%v) — %s", c.raw, got, ok, c.want, c.wantOK, c.comment)
		}
	}
}

func TestIsFiniteMemLimit(t *testing.T) {
	const gib = int64(1) << 30
	if !isFiniteMemLimit(gib) {
		t.Error("1 GiB must be finite")
	}
	if isFiniteMemLimit(0) || isFiniteMemLimit(-5) {
		t.Error("non-positive must not be finite")
	}
	if isFiniteMemLimit(int64(1) << 62) {
		t.Error("unlimited sentinel (2^62) must not be treated as finite")
	}
}

func TestCheckMemoryBackstop_NotYetRun(t *testing.T) {
	withCachedMemoryBackstopState(t)
	memoryBackstopState.Store(memoryBackstopStatus{})
	c := checkMemoryBackstop()
	if c.Code != "memory_backstop" || c.Status != diagOK {
		t.Errorf("got %+v, want ok memory_backstop", c)
	}
}

func TestCheckMemoryBackstop_OperatorPinned(t *testing.T) {
	withCachedMemoryBackstopState(t)
	memoryBackstopState.Store(memoryBackstopStatus{Mode: memBackstopOperatorPinned, Pinned: "500MiB"})
	c := checkMemoryBackstop()
	if c.Status != diagOK || !strings.Contains(c.Message, "500MiB") {
		t.Errorf("got %+v, want ok message mentioning the pinned value", c)
	}
}

func TestCheckMemoryBackstop_Active(t *testing.T) {
	withCachedMemoryBackstopState(t)
	memoryBackstopState.Store(memoryBackstopStatus{Mode: memBackstopActive, SoftMiB: 800, ContainerMiB: 1000})
	c := checkMemoryBackstop()
	if c.Status != diagOK || !strings.Contains(c.Message, "800 MiB") || !strings.Contains(c.Message, "1000 MiB") {
		t.Errorf("got %+v, want ok message mentioning soft + container MiB", c)
	}
}

func TestCheckMemoryBackstop_CapTooSmall(t *testing.T) {
	withCachedMemoryBackstopState(t)
	memoryBackstopState.Store(memoryBackstopStatus{Mode: memBackstopCapTooSmall, ContainerMiB: 64})
	c := checkMemoryBackstop()
	if c.Status != diagWarn || c.OperatorAction == "" {
		t.Errorf("got %+v, want warn with a non-empty operator action", c)
	}
}

func TestCheckMemoryBackstop_NotDetected(t *testing.T) {
	withCachedMemoryBackstopState(t)
	memoryBackstopState.Store(memoryBackstopStatus{Mode: memBackstopNotDetected})
	c := checkMemoryBackstop()
	if c.Status != diagOK {
		t.Errorf("got %+v, want ok (no container limit is a normal bare-host posture)", c)
	}
}

// TestInitMemoryBackstop_OperatorPinned exercises the one code path of
// initMemoryBackstop that does not depend on reading real cgroup files: an
// operator-set GOMEMLIMIT short-circuits detection and is cached verbatim.
func TestInitMemoryBackstop_OperatorPinned(t *testing.T) {
	withCachedMemoryBackstopState(t)
	t.Setenv("GOMEMLIMIT", "321MiB")
	initMemoryBackstop()
	st := loadMemoryBackstopStatus()
	if st.Mode != memBackstopOperatorPinned || st.Pinned != "321MiB" {
		t.Errorf("got %+v, want operator_pinned with Pinned=321MiB", st)
	}
}
