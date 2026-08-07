package mcpacceptance

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Mode selects the artifact-verification policy.
type Mode string

const (
	// ModeAuthoritative requires a matching expected digest AND provenance binding
	// before any traffic. Its evidence is marked authoritative:true.
	ModeAuthoritative Mode = "authoritative"
	// ModeDev is the CI/self-test path against a locally built binary. Its evidence
	// is unmistakably marked authoritative:false and can never be accepted as
	// qualification evidence. Dev mode NEVER silently satisfies an authoritative run.
	ModeDev Mode = "dev"
)

// Bounded timeout defaults and strict maxima. No unbounded waits are ever used.
const (
	defaultStartupTimeout  = 30 * time.Second
	maxStartupTimeout      = 3 * time.Minute
	defaultRequestTimeout  = 10 * time.Second
	maxRequestTimeout      = 60 * time.Second
	defaultShutdownTimeout = 20 * time.Second
	maxShutdownTimeout     = 90 * time.Second
	defaultRestartTimeout  = 45 * time.Second
	maxRestartTimeout      = 3 * time.Minute
)

// Spec is the operator-facing acceptance specification. It references identity
// material by file path (never inline secrets). In dev mode the environment may be
// omitted and the harness generates an ephemeral two-tenant fixture.
type Spec struct {
	Mode        Mode         `json:"mode"`
	Artifact    ArtifactSpec `json:"artifact"`
	Environment *EnvSpec     `json:"environment,omitempty"`
	Run         RunControl   `json:"run"`
	EvidenceDir string       `json:"evidence_dir"`
}

// ArtifactSpec identifies the binary under test and the authoritative-verification
// material. For an authoritative run, ExpectedDigest and Provenance are mandatory.
type ArtifactSpec struct {
	BinaryPath           string          `json:"binary_path"`
	ExpectedDigest       string          `json:"expected_digest,omitempty"` // sha256:<hex>
	ExpectedVersion      string          `json:"expected_version,omitempty"`
	ExpectedSourceCommit string          `json:"expected_source_commit,omitempty"`
	Provenance           *ProvenanceSpec `json:"provenance,omitempty"`
}

// ProvenanceSpec carries the result of an out-of-band verification the operator
// performed with the ACCEPTED verifier (cosign keyless against the pinned
// identity). The harness does NOT re-implement signature verification; it binds
// the operator's verified digest to the exact hashed binary. A missing or
// mismatched provenance block fails an authoritative run — it is never a silent
// downgrade to non-authoritative.
type ProvenanceSpec struct {
	Verifier       string `json:"verifier"`        // e.g. "cosign-keyless"
	Identity       string `json:"identity"`        // pinned issuer/SAN the operator verified against
	VerifiedDigest string `json:"verified_digest"` // sha256:<hex> the operator verified; must equal the hashed binary
}

// EnvSpec is the operator-provided qualification environment. Every field is an
// operator DECISION; the harness never invents hosts, issuers, tenants, or paths.
type EnvSpec struct {
	BindHost          string   `json:"bind_host"`
	OAuthIssuer       string   `json:"oauth_issuer"`
	CanonicalResource string   `json:"canonical_resource"`
	RequiredScopes    []string `json:"required_scopes"`
	AcceptedClientIDs []string `json:"accepted_client_ids"`
	TenantA           string   `json:"tenant_a"`
	TenantB           string   `json:"tenant_b"`
	ServerA           string   `json:"server_a"`
	ServerB           string   `json:"server_b"`
	// Identity material by path (public + private references stay on disk, never
	// enter the evidence bundle).
	TLSCertFile    string `json:"tls_cert_file"`
	TLSKeyFile     string `json:"tls_key_file"`
	ServerCAFile   string `json:"server_ca_file"`   // CA the harness trusts for the listener TLS
	ClientCAFile   string `json:"client_ca_file"`   // mTLS client CA the listener requires
	ClientCertFile string `json:"client_cert_file"` // mTLS client cert (for the mTLS scenario)
	ClientKeyFile  string `json:"client_key_file"`
	TrustedJWKS    string `json:"trusted_jwks_file"`
	// SigningKeyFile is the ES256 private key (PEM) the harness uses to mint the
	// tenant-A/tenant-B bearer tokens for the run. It is a file reference; its bytes
	// never appear in evidence.
	SigningKeyFile string `json:"signing_key_file"`
	SigningKID     string `json:"signing_kid"`
}

// RunControl bounds every wait. Zero fields fall back to safe defaults; values
// above the strict maximum are clamped down (never up).
type RunControl struct {
	StartupTimeout  Duration `json:"startup_timeout"`
	RequestTimeout  Duration `json:"request_timeout"`
	ShutdownTimeout Duration `json:"shutdown_timeout"`
	RestartTimeout  Duration `json:"restart_timeout"`
}

// Duration is a JSON-friendly time.Duration ("30s", "2m").
type Duration time.Duration

// UnmarshalJSON accepts a duration string ("30s", "2m") or a bare number of seconds.
func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		// Also accept a bare number of seconds.
		var n int64
		if err2 := json.Unmarshal(b, &n); err2 == nil {
			*d = Duration(time.Duration(n) * time.Second)
			return nil
		}
		return err
	}
	if s == "" {
		*d = 0
		return nil
	}
	pd, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	*d = Duration(pd)
	return nil
}

// MarshalJSON renders the duration as its string form ("30s").
func (d Duration) MarshalJSON() ([]byte, error) { return json.Marshal(time.Duration(d).String()) }

// resolved applies the default when zero and clamps to the strict maximum.
func resolved(v Duration, def, maxD time.Duration) time.Duration {
	d := time.Duration(v)
	if d <= 0 {
		return def
	}
	if d > maxD {
		return maxD
	}
	return d
}

func (r RunControl) startup() time.Duration {
	return resolved(r.StartupTimeout, defaultStartupTimeout, maxStartupTimeout)
}
func (r RunControl) request() time.Duration {
	return resolved(r.RequestTimeout, defaultRequestTimeout, maxRequestTimeout)
}
func (r RunControl) shutdown() time.Duration {
	return resolved(r.ShutdownTimeout, defaultShutdownTimeout, maxShutdownTimeout)
}
func (r RunControl) restart() time.Duration {
	return resolved(r.RestartTimeout, defaultRestartTimeout, maxRestartTimeout)
}

// LoadSpec reads and validates an acceptance spec JSON file.
func LoadSpec(path string) (*Spec, error) {
	clean := filepath.Clean(path)
	b, err := os.ReadFile(clean) // #nosec G304 -- operator-supplied spec path
	if err != nil {
		return nil, fmt.Errorf("read spec: %w", err)
	}
	var sp Spec
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&sp); err != nil {
		return nil, fmt.Errorf("decode spec: %w", err)
	}
	if err := sp.Validate(); err != nil {
		return nil, err
	}
	return &sp, nil
}

// Validate enforces the mode/artifact/provenance contract.
func (s *Spec) Validate() error {
	if s.Artifact.BinaryPath == "" {
		return errors.New("spec: artifact.binary_path is required")
	}
	if s.EvidenceDir == "" {
		return errors.New("spec: evidence_dir is required")
	}
	switch s.Mode {
	case ModeAuthoritative:
		if s.Artifact.ExpectedDigest == "" {
			return errors.New("spec: authoritative run requires artifact.expected_digest")
		}
		if s.Artifact.Provenance == nil || s.Artifact.Provenance.VerifiedDigest == "" {
			return errors.New("spec: authoritative run requires artifact.provenance.verified_digest (no silent downgrade)")
		}
		if s.Environment == nil {
			return errors.New("spec: authoritative run requires an explicit environment")
		}
	case ModeDev:
		// Dev mode may omit environment; the harness generates an ephemeral fixture.
	default:
		return fmt.Errorf("spec: mode must be %q or %q", ModeAuthoritative, ModeDev)
	}
	return nil
}

// ConfigHash is a deterministic sha256 over the canonical spec (which references
// secrets only by path — safe to hash and record).
func (s *Spec) ConfigHash() (string, error) {
	cj, err := canonicalJSON(s)
	if err != nil {
		return "", err
	}
	return sha256Bytes(cj), nil
}
