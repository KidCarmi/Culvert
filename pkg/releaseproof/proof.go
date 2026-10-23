// Package releaseproof verifies existing signed catalog evidence independently
// of its transport. It performs no network or filesystem access and has no
// permissive mode. Callers own policy provenance, durable replay floors and
// whether an already-authorized recovery may use an expired catalog.
package releaseproof

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"google.golang.org/protobuf/encoding/protojson"
)

// Evidence bounds, release signer identity, and tolerated clock skew.
const (
	// MaxDocumentBytes bounds each untrusted evidence document before parsing.
	MaxDocumentBytes = 1 << 20
	OfficialIssuer   = "https://token.actions.githubusercontent.com"
	OfficialSANRegex = `^https://github\.com/KidCarmi/Culvert/\.github/workflows/ci\.yml@refs/tags/v.*$`
	ClockSkew        = 5 * time.Minute
)

//go:embed trusted_root.json
var defaultRoot []byte

// DefaultPolicy returns baked public Sigstore trust with host-owned repositories.
func DefaultPolicy(catalogRepo, proxyRepo string) Policy {
	return Policy{TrustedRootJSON: append([]byte(nil), defaultRoot...), Issuer: OfficialIssuer, SANRegex: OfficialSANRegex, CatalogRepository: catalogRepo, ProxyRepository: proxyRepo}
}

// Evidence carries exact signed bytes. JSON encodes byte slices as base64 so
// envelope serialization never reformats the signed index or hashed manifest.
type Evidence struct {
	ReleaseID      string `json:"release_id"`
	Index          []byte `json:"index"`
	SigstoreBundle []byte `json:"sigstore_bundle,omitempty"`
	Signature      []byte `json:"signature,omitempty"`
	Manifest       []byte `json:"manifest"`
}

// Policy must come from the verifier host, never from an API request. Public
// Ed25519 keys support the existing offline catalog format without new secrets.
type Policy struct {
	TrustedRootJSON                    []byte
	Issuer, SANRegex                   string
	CatalogRepository, ProxyRepository string
	Ed25519Keys                        map[string][]byte
}

// Verifier binds signed catalog evidence to an independently configured host policy.
type Verifier struct {
	sigstore               *verify.Verifier
	identity               verify.CertificateIdentity
	keys                   map[string]ed25519.PublicKey
	catalogRepo, proxyRepo string
}

// Authorization contains verified identity and freshness metadata, not caller assertions.
type Authorization struct {
	Ref            string    `json:"ref"`
	ReleaseID      string    `json:"release_id"`
	VersionID      string    `json:"version_id"`
	MinUpgradeFrom string    `json:"min_upgrade_from,omitempty"`
	CatalogVersion int       `json:"catalog_version"`
	GeneratedAt    time.Time `json:"generated_at"`
	ExpiresAt      time.Time `json:"expires_at"`
}

var (
	idRE     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	digestRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	repoRE   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/:-]{0,254}$`)
)

// NewVerifier validates and copies host trust material; it has no permissive mode.
func NewVerifier(p Policy) (*Verifier, error) {
	if !validRepo(p.CatalogRepository) || !validRepo(p.ProxyRepository) {
		return nil, errors.New("release proof: invalid host repository policy")
	}
	v := &Verifier{catalogRepo: p.CatalogRepository, proxyRepo: p.ProxyRepository, keys: make(map[string]ed25519.PublicKey)}
	for id, key := range p.Ed25519Keys {
		if !idRE.MatchString(id) || len(key) != ed25519.PublicKeySize {
			return nil, errors.New("release proof: invalid host signing key")
		}
		v.keys[id] = append(ed25519.PublicKey(nil), key...)
	}
	if len(p.TrustedRootJSON) != 0 {
		if p.Issuer == "" || !strings.HasPrefix(p.SANRegex, "^") || !strings.HasSuffix(p.SANRegex, "$") {
			return nil, errors.New("release proof: exact issuer and anchored identity required")
		}
		tm, err := root.NewTrustedRootFromJSON(p.TrustedRootJSON)
		if err != nil {
			return nil, fmt.Errorf("release proof: trust root: %w", err)
		}
		v.sigstore, err = verify.NewVerifier(tm, verify.WithTransparencyLog(1), verify.WithIntegratedTimestamps(1))
		if err != nil {
			return nil, fmt.Errorf("release proof: verifier: %w", err)
		}
		v.identity, err = verify.NewShortCertificateIdentity(p.Issuer, "", "", p.SANRegex)
		if err != nil {
			return nil, fmt.Errorf("release proof: identity: %w", err)
		}
	}
	if v.sigstore == nil && len(v.keys) == 0 {
		return nil, errors.New("release proof: no host trust configured")
	}
	return v, nil
}

func validRepo(s string) bool {
	if !repoRE.MatchString(s) || strings.Contains(s, "@") || strings.HasSuffix(s, "/") {
		return false
	}
	// A colon is allowed in a registry authority, never in the final image name.
	last := s[strings.LastIndex(s, "/")+1:]
	return !strings.Contains(last, ":")
}

// Verify authenticates exact evidence and requires a currently fresh catalog.
func (v *Verifier) Verify(e Evidence, targetRef string, now time.Time) (Authorization, error) {
	a, err := v.VerifyAuthenticity(e, targetRef)
	if err != nil {
		return Authorization{}, err
	}
	if err := a.CheckFreshness(now); err != nil {
		return Authorization{}, err
	}
	return a, nil
}

// CheckFreshness checks the signed catalog validity window with bounded clock skew.
func (a Authorization) CheckFreshness(now time.Time) error {
	if now.After(a.ExpiresAt.Add(ClockSkew)) || a.GeneratedAt.After(now.Add(ClockSkew)) {
		return errors.New("release proof: catalog expired or future dated")
	}
	return nil
}

// VerifyAuthenticity does NOT waive freshness for a new request. It exists for
// offline recovery of a previously durably accepted exact digest. The caller
// must establish that ledger membership before using this method.
func (v *Verifier) VerifyAuthenticity(e Evidence, targetRef string) (Authorization, error) {
	if v == nil {
		return Authorization{}, errors.New("release proof: verifier unavailable")
	}
	if !idRE.MatchString(e.ReleaseID) {
		return Authorization{}, errors.New("release proof: invalid release ID")
	}
	for _, b := range [][]byte{e.Index, e.Manifest, e.SigstoreBundle, e.Signature} {
		if len(b) > MaxDocumentBytes {
			return Authorization{}, errors.New("release proof: document too large")
		}
	}
	if len(e.Index) == 0 || len(e.Manifest) == 0 {
		return Authorization{}, errors.New("release proof: missing document")
	}
	if err := v.verifySignature(e); err != nil {
		return Authorization{}, err
	}
	return v.bindManifest(e, targetRef)
}

func (v *Verifier) verifySignature(e Evidence) error {
	// Match existing catalog precedence: when host Sigstore trust is configured,
	// an invalid present bundle never falls back to Ed25519. An explicitly
	// Ed25519-only host policy ignores sidecars for an unconfigured authority.
	if v.sigstore != nil && len(e.SigstoreBundle) > 0 {
		pb := new(protobundle.Bundle)
		if err := protojson.Unmarshal(e.SigstoreBundle, pb); err != nil {
			return errors.New("release proof: malformed Sigstore bundle")
		}
		b, err := bundle.NewBundle(pb)
		if err != nil {
			return errors.New("release proof: malformed Sigstore bundle")
		}
		if err = v.verifyEntity(e.Index, b); err != nil {
			return errors.New("release proof: Sigstore verification failed")
		}
		return nil
	}
	if len(v.keys) == 0 || len(e.Signature) == 0 {
		return errors.New("release proof: trusted signature required")
	}
	var env struct {
		SchemaVersion int    `json:"schema_version"`
		Alg           string `json:"alg"`
		KeyID         string `json:"key_id"`
		Sig           string `json:"sig"`
	}
	if json.Unmarshal(e.Signature, &env) != nil || env.SchemaVersion != 1 || env.Alg != "ed25519" {
		return errors.New("release proof: invalid signature envelope")
	}
	key, ok := v.keys[env.KeyID]
	sig, err := base64.StdEncoding.DecodeString(env.Sig)
	if !ok || err != nil || len(sig) != ed25519.SignatureSize || !ed25519.Verify(key, e.Index, sig) {
		return errors.New("release proof: signature verification failed")
	}
	return nil
}

func (v *Verifier) verifyEntity(index []byte, entity verify.SignedEntity) error {
	_, err := v.sigstore.Verify(entity, verify.NewPolicy(verify.WithArtifact(bytes.NewReader(index)), verify.WithCertificateIdentity(v.identity)))
	return err
}

type indexEntry struct {
	ReleaseID      string `json:"release_id"`
	VersionID      string `json:"version_id"`
	ManifestRef    string `json:"manifest_ref"`
	ManifestSHA256 string `json:"manifest_sha256"`
}
type indexFile struct {
	SchemaVersion  int          `json:"schema_version"`
	CatalogVersion int          `json:"catalog_version"`
	GeneratedAt    string       `json:"generated_at"`
	ExpiresAt      string       `json:"expires_at"`
	Releases       []indexEntry `json:"releases"`
}
type manifestFile struct {
	SchemaVersion  int    `json:"schema_version"`
	ReleaseID      string `json:"release_id"`
	VersionID      string `json:"version_id"`
	MinUpgradeFrom string `json:"min_upgrade_from"`
	Image          struct {
		Repo       string `json:"repo"`
		ListDigest string `json:"list_digest"`
	} `json:"image"`
}

func (v *Verifier) bindManifest(e Evidence, targetRef string) (Authorization, error) {
	idx, generated, expires, err := parseIndex(e.Index)
	if err != nil {
		return Authorization{}, err
	}
	selected, err := selectEntry(idx, e.ReleaseID)
	if err != nil {
		return Authorization{}, err
	}
	sum := sha256.Sum256(e.Manifest)
	if hex.EncodeToString(sum[:]) != selected.ManifestSHA256 {
		return Authorization{}, errors.New("release proof: manifest hash mismatch")
	}
	var m manifestFile
	if json.Unmarshal(e.Manifest, &m) != nil || m.SchemaVersion != 1 || m.ReleaseID != selected.ReleaseID || m.VersionID != selected.VersionID {
		return Authorization{}, errors.New("release proof: manifest identity mismatch")
	}
	if m.Image.Repo != v.catalogRepo || !digestRE.MatchString(m.Image.ListDigest) || targetRef != v.proxyRepo+"@"+m.Image.ListDigest {
		return Authorization{}, errors.New("release proof: target repository or digest mismatch")
	}
	if m.MinUpgradeFrom != "" && (!ValidVersion(m.MinUpgradeFrom) || !ValidVersion(m.VersionID)) {
		return Authorization{}, errors.New("release proof: malformed signed upgrade floor or target version")
	}
	return Authorization{Ref: targetRef, ReleaseID: m.ReleaseID, VersionID: m.VersionID, MinUpgradeFrom: m.MinUpgradeFrom, CatalogVersion: idx.CatalogVersion, GeneratedAt: generated, ExpiresAt: expires}, nil
}

func parseIndex(b []byte) (idx indexFile, generated, expires time.Time, err error) {
	if json.Unmarshal(b, &idx) != nil || idx.SchemaVersion != 1 || idx.CatalogVersion < 1 || len(idx.Releases) == 0 {
		return indexFile{}, time.Time{}, time.Time{}, errors.New("release proof: invalid catalog")
	}
	generated, gerr := time.Parse(time.RFC3339, idx.GeneratedAt)
	expires, eerr := time.Parse(time.RFC3339, idx.ExpiresAt)
	if gerr != nil || eerr != nil || !expires.After(generated) {
		return indexFile{}, time.Time{}, time.Time{}, errors.New("release proof: invalid catalog timestamps")
	}
	return idx, generated, expires, nil
}

func selectEntry(idx indexFile, releaseID string) (*indexEntry, error) {
	var selected *indexEntry
	ids, versions, refs := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for i := range idx.Releases {
		x := &idx.Releases[i]
		if !idRE.MatchString(x.ReleaseID) || x.VersionID == "" || x.ManifestRef == "" || ids[x.ReleaseID] || versions[x.VersionID] || refs[x.ManifestRef] {
			return nil, errors.New("release proof: duplicate or invalid release entry")
		}
		if len(x.ManifestSHA256) != 64 {
			return nil, errors.New("release proof: invalid manifest hash")
		}
		if _, err := hex.DecodeString(x.ManifestSHA256); err != nil || strings.ToLower(x.ManifestSHA256) != x.ManifestSHA256 {
			return nil, errors.New("release proof: invalid manifest hash")
		}
		ids[x.ReleaseID], versions[x.VersionID], refs[x.ManifestRef] = true, true, true
		if x.ReleaseID == releaseID {
			selected = x
		}
	}
	if selected == nil {
		return nil, errors.New("release proof: release absent from signed index")
	}
	return selected, nil
}
