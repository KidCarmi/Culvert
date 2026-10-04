package main

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"github.com/KidCarmi/Culvert/releaseproof"
)

func TestReleaseProofSnapshotSurvivesSourceAndRequestMutation(t *testing.T) {
	src, trust := signedSource(t, VerifyEnforce)
	cat, err := LoadVerifiedCatalog(src, trust)
	if err != nil {
		t.Fatal(err)
	}
	p := cat.releaseProof("rel_a")
	if p == nil || !bytes.Equal(p.Index, src.index) || !bytes.Equal(p.Signature, src.sig) {
		t.Fatal("verified source evidence was not retained exactly")
	}
	index := bytes.Clone(p.Index)
	manifest := bytes.Clone(p.Manifest)
	src.index[0] ^= 1
	src.sig[0] ^= 1
	for _, raw := range src.manifests {
		raw[0] ^= 1
	}
	p.Index[0] ^= 1
	p.Manifest[0] ^= 1
	fresh := cat.releaseProof("rel_a")
	if !bytes.Equal(fresh.Index, index) || !bytes.Equal(fresh.Manifest, manifest) || src.indexReads != 1 {
		t.Fatal("source/request mutation changed immutable dispatch evidence")
	}
	if cat.releaseProof("unknown") != nil {
		t.Fatal("unknown release obtained evidence")
	}
}

func TestReleaseProofDispatchCarriesTargetAndPriorExactBytes(t *testing.T) {
	src, trust := signedSource(t, VerifyEnforce)
	cat, err := LoadVerifiedCatalog(src, trust)
	if err != nil {
		t.Fatal(err)
	}
	d, provider := newDispatcher(t, cat, DispatchConfig{ProxyRepo: dispatchRepo})
	plan := d.Plan(DispatchTarget{ReleaseID: "rel_a"}, []string{dispatchRepo + "@" + digB}, DefaultDispatchOptions())
	if plan.Refused() || plan.Apply.ReleaseProof == nil || plan.Apply.PriorReleaseProof == nil {
		t.Fatalf("missing evidence: outcome=%s reason=%v", plan.Outcome, plan.Reason)
	}
	if plan.Apply.ReleaseProof.ReleaseID != "rel_a" || plan.Apply.PriorReleaseProof.ReleaseID != "rel_b" || provider.calls != 1 {
		t.Fatal("dispatch evidence mixed catalog snapshots or releases")
	}
	raw, err := json.Marshal(plan.Apply)
	if err != nil {
		t.Fatal(err)
	}
	var wire struct {
		Target releaseproof.Evidence `json:"release_proof"`
		Prior  releaseproof.Evidence `json:"prior_release_proof"`
	}
	if err := json.Unmarshal(raw, &wire); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire.Target.Index, src.index) || !bytes.Equal(wire.Prior.Signature, src.sig) {
		t.Fatal("wire encoding reformatted signed source bytes")
	}
}

func TestReleaseProofUnsignedCatalogDoesNotInventEvidence(t *testing.T) {
	cat := mustLoad(t, validSource())
	if cat.releaseProof("rel_a") != nil {
		t.Fatal("unsigned catalog invented host authorization")
	}
}

func TestReleaseProofBakedTrustMatchesProxy(t *testing.T) {
	raw, err := os.ReadFile("pkg/releaseproof/trusted_root.json")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, bakedSigstoreTrustedRootJSON) {
		t.Fatal("host and proxy baked Sigstore public trust drifted")
	}
	if releaseproof.OfficialIssuer != officialSigstoreIssuer || releaseproof.OfficialSANRegex != officialSigstoreSANRegex {
		t.Fatal("host and proxy release identities drifted")
	}
}
