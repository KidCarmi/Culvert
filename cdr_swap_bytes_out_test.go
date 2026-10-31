package main

// cdr_swap_bytes_out_test.go — culvert_cdr_bytes_out_total counts only
// sanitized bytes that survive the CHAOS-106 decompression check.
//
// runCDRStage's cdrSwap branch used to add the replacement body to
// statCDRBytesOut BEFORE the CHAOS-106 decompression check, so a sanitized
// replacement that was then refused as a decompression bomb was reported as
// delivered. The counter now moves only after the replacement survives the
// check; the negative control pins that an ordinary sanitized replacement is
// still counted in full.

import (
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	pb "github.com/KidCarmi/Sluice/proto/sluicev1"
)

// runSwapStage runs one CDR decision whose fake Sluice sanitizes the
// document into replacement, with the response's Content-Encoding ce.
func runSwapStage(t *testing.T, replacement []byte, ce string) (cdrStageDecision, *stageResponder) {
	t.Helper()
	resetCDRCountersAndCache(t)
	freshPolicyStore(t)
	sum := sha256.Sum256(replacement)
	pc, stop := newPooledFake(t, "swap", &fakeSluice{
		result: &pb.SanitizeResult{
			Status:          pb.Status_SANITIZED,
			SanitizedSize:   int64(len(replacement)),
			SanitizedSha256: sum[:],
		},
		replyChunks: [][]byte{replacement},
	})
	t.Cleanup(stop)
	withTempPool(t, pc)
	withActiveCDRConfig(t, CDRConfig{Enabled: true})

	br := &stageResponder{}
	r := httptest.NewRequestWithContext(t.Context(), http.MethodConnect, "https://files.example.com:443", http.NoBody)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://files.example.com/downloads/report.docx", http.NoBody)
	orig := []byte("original document bytes")
	dec := runCDRStage(r, req, orig, orig, "application/msword", ce, br,
		"files.example.com", sampleID.ClientIP, sampleID)
	return dec, br
}

func TestRunCDRStage_RefusedSwapIsNotCountedAsBytesOut(t *testing.T) {
	setScanDecompressRatio(t, 64)
	dec, br := runSwapStage(t, chaos106Bomb(t), "gzip")

	if !dec.blocked {
		t.Fatalf("a sanitized replacement that is a decompression bomb was not refused: blocked=%v body=%d", dec.blocked, len(dec.body))
	}
	if calls, _ := br.snapshot(); calls != 1 {
		t.Errorf("block emissions = %d, want 1", calls)
	}
	if n := atomic.LoadInt64(&statCDRBytesOut); n != 0 {
		t.Errorf("statCDRBytesOut = %d after the replacement was refused, want 0 — nothing was delivered", n)
	}
}

// Negative control: an ordinary sanitized replacement is delivered and counted.
func TestRunCDRStage_DeliveredSwapIsCountedAsBytesOut(t *testing.T) {
	setScanDecompressRatio(t, 64)
	replacement := []byte("SANITIZED_REPLACEMENT_BYTES")
	dec, br := runSwapStage(t, replacement, "")

	if dec.blocked {
		t.Fatal("an ordinary sanitized replacement was blocked")
	}
	if calls, _ := br.snapshot(); calls != 0 {
		t.Errorf("block emissions = %d, want 0", calls)
	}
	if n := atomic.LoadInt64(&statCDRBytesOut); n != int64(len(replacement)) {
		t.Errorf("statCDRBytesOut = %d, want the delivered %d", n, len(replacement))
	}
}
