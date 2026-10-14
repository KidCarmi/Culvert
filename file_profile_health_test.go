package main

import (
	"sync/atomic"
	"testing"
)

func TestCheckFileProfileResolution(t *testing.T) {
	orig := atomic.LoadInt64(&statFileProfileUnresolvedBlocked)
	t.Cleanup(func() { atomic.StoreInt64(&statFileProfileUnresolvedBlocked, orig) })

	atomic.StoreInt64(&statFileProfileUnresolvedBlocked, 0)
	if c := checkFileProfileResolution(); c.Code != "file_profile_resolution" || c.Status != diagOK || c.OperatorAction != "" {
		t.Fatalf("zero blocks: got %+v, want ok row without action", c)
	}

	atomic.StoreInt64(&statFileProfileUnresolvedBlocked, 3)
	c := checkFileProfileResolution()
	if c.Status != diagWarn || c.OperatorAction == "" {
		t.Fatalf("blocks>0: got %+v, want warn row with operator action", c)
	}
}

func TestCheckFileProfileResolution_RegisteredInOperatorContract(t *testing.T) {
	for _, c := range buildOperatorContract().Checks {
		if c.Code == "file_profile_resolution" {
			return
		}
	}
	t.Fatal("file_profile_resolution missing from /api/diagnostics contract")
}
