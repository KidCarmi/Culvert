package mcpacceptance

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
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
// In authoritative mode the harness consumes each of these values in the spawned
// artifact and PROVES it was consumed (QUAL-6.1); it never records a value it
// silently ignores.
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

	// ── QUAL-6.1 authoritative controls ─────────────────────────────────────────
	// GatewayPort is the operator-selected MCP Gateway listener port on the primary
	// (proc A). The Gateway binds BindHost:GatewayPort; the harness (and any external
	// supervisor) reaches the MCP boundary there. Auxiliary/negative-control processes
	// bind ephemeral ports on the same host.
	GatewayPort int `json:"gateway_port"`
	// TLSServerName is the server-name the harness validates the listener TLS cert
	// against. Optional; empty defaults to BindHost. The operator's server cert SAN
	// must cover it, otherwise the TLS scenario fails truthfully.
	TLSServerName string `json:"tls_server_name,omitempty"`
	// QualificationPolicyFile is the operator-owned Culvert qualification policy file
	// (the SAME production format the binary consumes at mcp.gateway
	// .qualification_policy_file). The harness passes THIS file into the spawned
	// config verbatim and never rewrites it; it never substitutes the dev fixture
	// policy in authoritative mode. Only its digest and the resulting runtime
	// revision/snapshot-hash enter evidence, never its source bytes.
	QualificationPolicyFile string `json:"qualification_policy_file"`
	// Telemetry is the operator-owned QUAL-3 durable-telemetry custody boundary. The
	// harness consumes these production fields on the primary EXACTLY, never a
	// temp-work-root equivalent, never generates or reads the KEK, and never deletes
	// these paths on cleanup.
	Telemetry *TelemetryEnv `json:"telemetry"`
	// Supervision is the operator-accessible Admin + metrics boundary for live
	// external supervision of the primary during the run. Credentials are file
	// references only; their bytes never enter evidence.
	Supervision *SupervisionEnv `json:"supervision"`
}

// TelemetryEnv is the operator-owned QUAL-3 telemetry configuration (production
// fields). The primary process consumes these paths verbatim; the restart scenario
// reuses the same data root + KEK + archive to prove durable persistence across a
// real process restart.
type TelemetryEnv struct {
	NodeID     string `json:"node_id"`
	DataDir    string `json:"data_dir"`
	KEKFile    string `json:"kek_file"`
	ArchiveDir string `json:"archive_dir"`
}

// SupervisionEnv is the operator-accessible Admin + metrics listener + credential
// configuration for the primary. Ports are operator-selected so an external
// supervisor knows where to look; credentials are supplied by PATH only (never a
// raw secret field). The admin UI and proxy/metrics listeners bind all interfaces
// (existing product behavior) and stay protected by their own auth + optional IP
// allowlist.
type SupervisionEnv struct {
	AdminPort         int    `json:"admin_port"`
	MetricsPort       int    `json:"metrics_port"`
	AdminUser         string `json:"admin_user"`
	AdminPasswordFile string `json:"admin_password_file"`
	MetricsTokenFile  string `json:"metrics_token_file"`
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
		if err := s.Environment.validateAuthoritative(); err != nil {
			return err
		}
	case ModeDev:
		// Dev mode may omit environment; the harness generates an ephemeral fixture.
	default:
		return fmt.Errorf("spec: mode must be %q or %q", ModeAuthoritative, ModeDev)
	}
	return nil
}

// validateAuthoritative enforces that EVERY authoritative environment control is
// present and structurally usable BEFORE any traffic (QUAL-6.1 no-fallback
// strictness). File EXISTENCE and content checks are deferred to the fixture
// loader (they need the filesystem); this is the structural, secret-free gate that
// makes a missing/invalid control fail at LoadSpec, never fall back to a dev
// fixture. It reads no files and never converts an invalid value to a default.
func (e *EnvSpec) validateAuthoritative() error {
	if err := validateBindHost(e.BindHost); err != nil {
		return err
	}
	if err := validatePort("gateway_port", e.GatewayPort); err != nil {
		return err
	}
	if e.QualificationPolicyFile == "" {
		return errors.New("spec: authoritative run requires environment.qualification_policy_file")
	}
	if err := e.validateTelemetryFields(); err != nil {
		return err
	}
	return e.validateSupervisionFields()
}

// validateTelemetryFields enforces the operator telemetry block is present and every
// required path is non-empty.
func (e *EnvSpec) validateTelemetryFields() error {
	if e.Telemetry == nil {
		return errors.New("spec: authoritative run requires environment.telemetry")
	}
	for _, f := range []struct{ name, val string }{
		{"telemetry.node_id", e.Telemetry.NodeID},
		{"telemetry.data_dir", e.Telemetry.DataDir},
		{"telemetry.kek_file", e.Telemetry.KEKFile},
		{"telemetry.archive_dir", e.Telemetry.ArchiveDir},
	} {
		if f.val == "" {
			return fmt.Errorf("spec: authoritative run requires environment.%s", f.name)
		}
	}
	return nil
}

// validateSupervisionFields enforces the operator supervision block: bounded distinct
// ports and path-only credential references (never an inline secret).
func (e *EnvSpec) validateSupervisionFields() error {
	if e.Supervision == nil {
		return errors.New("spec: authoritative run requires environment.supervision")
	}
	if err := validatePort("supervision.admin_port", e.Supervision.AdminPort); err != nil {
		return err
	}
	if err := validatePort("supervision.metrics_port", e.Supervision.MetricsPort); err != nil {
		return err
	}
	if e.Supervision.AdminPort == e.Supervision.MetricsPort || e.Supervision.AdminPort == e.GatewayPort || e.Supervision.MetricsPort == e.GatewayPort {
		return errors.New("spec: authoritative gateway_port, supervision.admin_port and supervision.metrics_port must be distinct")
	}
	for _, f := range []struct{ name, val string }{
		{"supervision.admin_user", e.Supervision.AdminUser},
		{"supervision.admin_password_file", e.Supervision.AdminPasswordFile},
		{"supervision.metrics_token_file", e.Supervision.MetricsTokenFile},
	} {
		if f.val == "" {
			return fmt.Errorf("spec: authoritative run requires environment.%s (path reference; never an inline secret)", f.name)
		}
	}
	return nil
}

// validateBindHost validates an operator-selected bind host conservatively. It
// rejects an empty host and a wildcard bind (0.0.0.0 / ::), and requires the value
// to be either a parseable IP or a plausible hostname. It NEVER converts an invalid
// host to loopback — an invalid host fails here, before any traffic.
func validateBindHost(host string) error {
	if host == "" {
		return errors.New("spec: authoritative run requires a non-empty environment.bind_host")
	}
	if host == "0.0.0.0" || host == "::" || host == "[::]" {
		return errors.New("spec: environment.bind_host must be a specific interface; a wildcard bind is not permitted")
	}
	if net.ParseIP(host) != nil {
		return nil
	}
	// Plausible hostname: non-empty labels, no spaces or path/scheme characters.
	if strings.ContainsAny(host, " /\\:@") || len(host) > 253 {
		return fmt.Errorf("spec: environment.bind_host %q is not a valid host", host)
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" {
			return fmt.Errorf("spec: environment.bind_host %q has an empty label", host)
		}
	}
	return nil
}

// validatePort bounds a TCP port to the operator-selectable range. Port 0
// (ephemeral) is intentionally NOT accepted for an operator-supervised endpoint —
// a supervisor must know the port in advance.
func validatePort(name string, p int) error {
	if p < 1 || p > 65535 {
		return fmt.Errorf("spec: authoritative %s must be in 1..65535 (a fixed, operator-known port)", name)
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

// effectiveConfigHash folds the canonical spec together with the resolved
// content-level controls that actually ran (extras). It is the invariant-bearing
// acceptance config hash: it MUST change when an effective operator control changes
// (e.g. the policy file CONTENT, not merely its path) and must NOT change for a
// harness-internal temp path (never in the spec). With no extras it equals
// ConfigHash, so dev mode is byte-identical. Extras are sorted so ordering is not
// load-bearing.
func (s Spec) effectiveConfigHash(extra ...string) (string, error) {
	cj, err := canonicalJSON(s)
	if err != nil {
		return "", err
	}
	if len(extra) == 0 {
		return sha256Bytes(cj), nil
	}
	ex := append([]string(nil), extra...)
	sort.Strings(ex)
	return sha256Bytes([]byte(sha256Bytes(cj) + "\n" + strings.Join(ex, "\n"))), nil
}
