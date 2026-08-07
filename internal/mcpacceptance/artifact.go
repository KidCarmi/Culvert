package mcpacceptance

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
)

// hashBinary returns sha256:<hex> of the on-disk artifact.
func hashBinary(path string) (string, error) {
	f, err := os.Open(path) // #nosec G304 -- operator-supplied artifact path
	if err != nil {
		return "", err
	}
	defer f.Close() //nolint:errcheck
	hsh := sha256.New()
	if _, err := io.Copy(hsh, f); err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(hsh.Sum(nil)), nil
}

// bindArtifact computes the artifact identity and enforces the mode's
// verification policy BEFORE any traffic. For an authoritative run the expected
// digest and the operator's provenance-verified digest must both equal the hashed
// binary — otherwise the run fails here, before the binary is ever started. Dev
// mode records the digest and marks the result non-authoritative. There is no
// silent downgrade: a flag can never turn a dev binary into authoritative
// evidence, and a missing/mismatched provenance fails an authoritative run.
func bindArtifact(spec *Spec) (ArtifactIdentity, error) {
	digest, err := hashBinary(spec.Artifact.BinaryPath)
	if err != nil {
		return ArtifactIdentity{}, fmt.Errorf("hash artifact: %w", err)
	}
	id := ArtifactIdentity{
		Path:         spec.Artifact.BinaryPath,
		Digest:       digest,
		SourceCommit: spec.Artifact.ExpectedSourceCommit,
	}
	switch spec.Mode {
	case ModeAuthoritative:
		if spec.Artifact.ExpectedDigest != digest {
			return id, fmt.Errorf("authoritative artifact digest mismatch: expected %s, hashed %s", spec.Artifact.ExpectedDigest, digest)
		}
		p := spec.Artifact.Provenance
		if p == nil || p.VerifiedDigest != digest {
			return id, fmt.Errorf("authoritative run requires provenance verified_digest == hashed binary (accepted out-of-band verifier); refusing to fabricate authoritative status")
		}
		if spec.Artifact.ExpectedSourceCommit == "" {
			return id, fmt.Errorf("authoritative run requires an unambiguous source commit")
		}
		id.Verification = "provenance-bound"
		id.Authoritative = true
	case ModeDev:
		// Dev/self-test: digest recorded, never authoritative.
		if spec.Artifact.ExpectedDigest != "" && spec.Artifact.ExpectedDigest != digest {
			return id, fmt.Errorf("dev artifact digest mismatch: expected %s, hashed %s", spec.Artifact.ExpectedDigest, digest)
		}
		id.Verification = "unverified"
		id.Authoritative = false
	}
	return id, nil
}

// pinBinary copies the exact bytes that were hashed to a harness-owned path and
// verifies the copy's digest equals expectedDigest, then returns the copy path.
// Running the copy binds the reported digest to the bytes actually executed
// (closing the hash-then-exec TOCTOU on the caller-supplied path). The copy is
// mode 0500 (owner read+exec only).
func pinBinary(src, dst, expectedDigest string) (string, error) {
	in, err := os.Open(src) // #nosec G304 -- operator-supplied artifact path
	if err != nil {
		return "", fmt.Errorf("pin artifact open: %w", err)
	}
	defer in.Close()                                                        //nolint:errcheck
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o500) // #nosec G304 -- harness-owned work dir
	if err != nil {
		return "", fmt.Errorf("pin artifact create: %w", err)
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return "", fmt.Errorf("pin artifact copy: %w", err)
	}
	if err := out.Close(); err != nil {
		return "", fmt.Errorf("pin artifact close: %w", err)
	}
	got, err := hashBinary(dst)
	if err != nil {
		return "", fmt.Errorf("pin artifact rehash: %w", err)
	}
	if got != expectedDigest {
		return "", fmt.Errorf("pinned copy digest %s != expected %s", got, expectedDigest)
	}
	return dst, nil
}

// probeVersion reads the binary's embedded version from GET /healthz (the only
// surface that exposes it). Returns "" if unavailable.
func probeVersion(ctx context.Context, cli *http.Client, uiPort int) string {
	url := fmt.Sprintf("http://127.0.0.1:%d/healthz", uiPort)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return ""
	}
	resp, err := cli.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close() //nolint:errcheck
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	var hv struct {
		Version string `json:"version"`
	}
	if json.Unmarshal(raw, &hv) != nil {
		return ""
	}
	return hv.Version
}
