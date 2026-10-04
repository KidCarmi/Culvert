package server

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/releaseproof"
)

// Existing orchestration fixtures explicitly isolate the release policy. Real
// signature and durable-ledger cases live in releaseproof/releasetrust tests.
type allowReleaseTrustForTest struct{}

func (allowReleaseTrustForTest) Check(string, *releaseproof.Evidence) error { return nil }
func (allowReleaseTrustForTest) Prepare(string, *releaseproof.Evidence, string, *releaseproof.Evidence) error {
	return nil
}
func (allowReleaseTrustForTest) AdmitRollback(string, *releaseproof.Evidence) error { return nil }
func (allowReleaseTrustForTest) Known(string) error                                 { return nil }

func TestReleaseTrustMissingStopsSharedMutation(t *testing.T) {
	s := &Server{}
	ref := "ghcr.io/kidcarmi/culvert@sha256:" + strings.Repeat("a", 64)
	if _, _, err := s.tagAndUp(context.Background(), ref, nil); err == nil {
		t.Fatal("tag reached without authorization")
	}
	if _, _, err := s.rollbackPull(func() string { return ref }, &rollbackAccumulator{})(context.Background()); err == nil {
		t.Fatal("pull reached without authorization")
	}
	if err := s.checkRelease(ref, nil); err == nil {
		t.Fatal("proofless apply accepted")
	}
	if err := s.prepareRelease(ref, nil, ref, nil); err == nil {
		t.Fatal("unsigned baseline accepted")
	}
}

func TestReleaseProofBodyCapIsRouteSpecific(t *testing.T) {
	body := `{"release_proof":{"release_id":"r","index":"` + strings.Repeat("A", 32<<10) + `"}}`
	var dst struct {
		Proof *releaseproof.Evidence `json:"release_proof"`
	}
	if err := decodeJSONBody(httptest.NewRequest("POST", "/", strings.NewReader(body)), &dst); err == nil {
		t.Fatal("ordinary body cap expanded")
	}
	if err := decodeJSONBodyLimit(httptest.NewRequest("POST", "/", strings.NewReader(body)), &dst, maxProofBodyBytes); err != nil {
		t.Fatal(err)
	}
	tooLarge := `{"release_proof":{"index":"` + strings.Repeat("A", maxProofBodyBytes) + `"}}`
	if err := decodeJSONBodyLimit(httptest.NewRequest("POST", "/", strings.NewReader(tooLarge)), &dst, maxProofBodyBytes); err == nil {
		t.Fatal("oversized proof body accepted")
	}
}
