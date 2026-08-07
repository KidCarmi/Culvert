// Package mcpacceptance implements an operator-runnable, artifact-bound Observe
// Acceptance Harness for the Culvert MCP Gateway (QUAL-6).
//
// The harness drives a BUILT culvert binary through its REAL production
// boundaries — a real TLS/mTLS listener, real OAuth authentication, the real
// Admin HTTP API, real /metrics, and the real on-disk encrypted telemetry spool
// and archive — and emits a deterministic, tamper-evident, secret-free evidence
// bundle bound to the exact tested artifact.
//
// It is strictly an ACCEPTANCE TEST HARNESS: it never begins Observe, never calls
// BeginWindow, never creates a qualification-duration window, never promotes a
// Catalog tool, never enables the executor/upstream/credential broker, never
// materializes a credential, never alters rollout mode, and never unlocks
// Production. Every "live" criterion is proven at the production binary boundary,
// never by calling an internal Go constructor.
package mcpacceptance

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// EvidenceSchemaVersion is the schema version of the acceptance evidence bundle.
// Bump only on a breaking change to the on-disk bundle shape.
const EvidenceSchemaVersion = 1

// Status is the outcome of a single acceptance criterion.
type Status string

const (
	// StatusPass — the criterion was proven at the required boundary.
	StatusPass Status = "PASS"
	// StatusFail — the criterion ran and did not meet its expected result.
	StatusFail Status = "FAIL"
	// StatusSkip — the criterion is explicitly out of Observe scope (never a
	// required criterion) and was deliberately not run.
	StatusSkip Status = "SKIP"
)

// CriterionResult is the bounded, secret-free record of one acceptance criterion.
// Observed carries only a safe classification (a status code, a bounded reason
// code, a count) — never a token, key, raw argument, tool output, or path secret.
type CriterionResult struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Group    string   `json:"group"`
	Required bool     `json:"required"`
	Status   Status   `json:"status"`
	Expected string   `json:"expected"`
	Observed string   `json:"observed"`
	Reason   string   `json:"reason,omitempty"`
	Evidence []string `json:"evidence,omitempty"`
	StartMS  int64    `json:"start_ms"`
	EndMS    int64    `json:"end_ms"`
}

// ArtifactIdentity binds the acceptance result to the exact tested artifact.
type ArtifactIdentity struct {
	Path          string `json:"path"`
	Digest        string `json:"digest"`        // sha256:<hex> of the on-disk binary
	Version       string `json:"version"`       // from GET /healthz
	SourceCommit  string `json:"source_commit"` // operator-supplied / provenance-bound
	Verification  string `json:"verification"`  // "digest-match" | "provenance-bound" | "unverified"
	Authoritative bool   `json:"authoritative"`
}

// TenantMatrixCell records one direction of the two-tenant live matrix.
type TenantMatrixCell struct {
	Token       string `json:"token"`  // "A" | "B" (which tenant minted the token)
	Server      string `json:"server"` // "A" | "B" (which tenant owns the addressed server)
	Expected    string `json:"expected"`
	Observed    string `json:"observed"`
	CrossTenant bool   `json:"cross_tenant"`
	Status      Status `json:"status"`
}

// Summary is the top-level acceptance evidence summary (bundle.json).
type Summary struct {
	SchemaVersion        int                `json:"schema_version"`
	Authoritative        bool               `json:"authoritative"`
	HarnessVersion       string             `json:"harness_version"`
	HarnessSourceSHA     string             `json:"harness_source_sha,omitempty"`
	Artifact             ArtifactIdentity   `json:"artifact"`
	AcceptanceConfigHash string             `json:"acceptance_config_hash"`
	RunID                string             `json:"run_id"`
	StartUTC             string             `json:"acceptance_run_start_utc"`
	EndUTC               string             `json:"acceptance_run_end_utc"`
	Overall              Status             `json:"overall"`
	PolicyRevision       uint64             `json:"policy_revision"`
	PolicySnapshotHash   string             `json:"policy_snapshot_hash"`
	InventoryIdentity    string             `json:"inventory_identity"`
	InventoryRevision    uint64             `json:"inventory_revision"`
	TenantMatrix         []TenantMatrixCell `json:"tenant_matrix"`
	TelemetrySummary     TelemetrySummary   `json:"telemetry_summary"`
	RestartResult        Status             `json:"restart_result"`
	EmergencyDisable     Status             `json:"emergency_disable_result"`
	NonExecution         Status             `json:"non_execution_result"`
	Criteria             []CriterionResult  `json:"criteria"`
	// Notes carries bounded, non-authoritative operator notes (e.g. a documented
	// known limitation such as the absent live user-rule ALLOW tools/call path).
	Notes []string `json:"notes,omitempty"`
}

// TelemetrySummary is the bounded telemetry/spool/export health snapshot.
type TelemetrySummary struct {
	TelemetryReady       bool   `json:"telemetry_ready"`
	DecisionTelemetry    string `json:"decision_telemetry"`
	EncryptionAvailable  bool   `json:"encryption_available"`
	Committed            bool   `json:"decision_committed"`
	DenialAggregated     bool   `json:"denial_aggregated"`
	ExportedAfterRestart bool   `json:"evidence_survived_restart"`
}

// canonicalJSON marshals v deterministically: encoding/json emits struct fields
// in declaration order and map keys sorted, so the output is byte-stable for a
// given value. Used for the summary, per-criterion records, and the manifest.
func canonicalJSON(v any) ([]byte, error) {
	var sb strings.Builder
	enc := json.NewEncoder(&sb)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return []byte(sb.String()), nil
}

// ManifestEntry is one file's tamper-evidence record.
type ManifestEntry struct {
	File   string `json:"file"`
	Digest string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}

// Manifest is the per-file digest set plus the overall manifest digest. It makes
// accidental mutation of the bundle detectable. It is NOT a signature and confers
// no authorization — the bundle is test evidence, never a rollout receipt.
type Manifest struct {
	SchemaVersion  int             `json:"schema_version"`
	Entries        []ManifestEntry `json:"entries"`
	ManifestDigest string          `json:"manifest_digest"`
}

// jwtRE matches a three-segment base64url JWT beginning with a JSON header ("eyJ").
var jwtRE = regexp.MustCompile(`eyJ[A-Za-z0-9_-]{4,}\.eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{8,}`)

// secretPatterns are generic high-signal secret shapes scanned in every emitted
// byte of the bundle regardless of the known-value registry.
var secretPatterns = []struct {
	name string
	re   *regexp.Regexp
}{
	{"private_key_pem", regexp.MustCompile(`-{5}BEGIN (?:EC |RSA |OPENSSH |PGP )?PRIVATE KEY-{5}`)},
	{"bearer_jwt", jwtRE},
}

// SecretScan holds the set of exact sensitive values the harness generated so the
// finalized bundle can be proven not to contain any of them. It also applies the
// generic pattern scan. A hit fails the run; only a bounded classification is
// reported, never the offending value.
type SecretScan struct {
	values map[string]string // value -> classification label
}

// NewSecretScan returns an empty registry.
func NewSecretScan() *SecretScan { return &SecretScan{values: map[string]string{}} }

// Add registers an exact sensitive value under a bounded classification label.
// Empty and very short values are ignored (they would false-positive on ordinary
// text and carry no secret entropy).
func (s *SecretScan) Add(label, value string) {
	if len(value) < 8 {
		return
	}
	s.values[value] = label
}

// Violation is a bounded, value-free record of a secret-containment failure.
type Violation struct {
	Classification string `json:"classification"`
	Location       string `json:"location"`
}

// Scan reads every file under dir and reports bounded violations for any known
// secret value or generic secret pattern found. The offending value is never
// included — only its classification and the file it appeared in.
func (s *SecretScan) Scan(dir string) ([]Violation, error) {
	var viols []Violation
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		b, err := os.ReadFile(path) // #nosec G304 G122 -- harness-owned evidence directory, not attacker-controlled
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, path)
		content := string(b)
		for val, label := range s.values {
			if strings.Contains(content, val) {
				viols = append(viols, Violation{Classification: label, Location: rel})
			}
		}
		for _, p := range secretPatterns {
			if p.re.MatchString(content) {
				viols = append(viols, Violation{Classification: p.name, Location: rel})
			}
		}
		return nil
	})
	// Deterministic ordering for stable evidence.
	sort.Slice(viols, func(i, j int) bool {
		if viols[i].Location != viols[j].Location {
			return viols[i].Location < viols[j].Location
		}
		return viols[i].Classification < viols[j].Classification
	})
	return viols, err
}

// sha256File returns sha256:<hex> of a file plus its byte length.
func sha256File(path string) (digest string, size int64, err error) {
	b, err := os.ReadFile(path) // #nosec G304 G122 -- harness-owned evidence directory, not attacker-controlled
	if err != nil {
		return "", 0, err
	}
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:]), int64(len(b)), nil
}

// sha256Bytes returns sha256:<hex> of b.
func sha256Bytes(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// buildManifest computes a deterministic per-file manifest over every file in dir
// EXCEPT manifest.json itself, then folds the sorted entries into one overall
// manifest digest.
func buildManifest(dir string) (*Manifest, error) {
	var entries []ManifestEntry
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(dir, path)
		if rel == "manifest.json" {
			return nil
		}
		dig, n, err := sha256File(path)
		if err != nil {
			return err
		}
		entries = append(entries, ManifestEntry{File: rel, Digest: dig, Bytes: n})
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].File < entries[j].File })
	m := &Manifest{SchemaVersion: EvidenceSchemaVersion, Entries: entries}
	// Overall digest = sha256 of the canonical entries list (order-stable).
	cj, err := canonicalJSON(entries)
	if err != nil {
		return nil, err
	}
	m.ManifestDigest = sha256Bytes(cj)
	return m, nil
}

// utcStamp formats a time as RFC3339 UTC to the second — a test-run timestamp
// only. It is NEVER an Observe/Shadow/Canary window or a qualification duration.
func utcStamp(t time.Time) string { return t.UTC().Format(time.RFC3339) }

// writeFile writes b to dir/name with 0600 (evidence may reference bounded state).
// dir and name are harness-owned constants (never operator/network input), so the
// join is not an untrusted path.
func writeFile(dir, name string, b []byte) error {
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	return os.WriteFile(p, b, 0o600) // #nosec G304 -- harness-owned evidence path, not attacker-controlled
}

// FinalizeError classifies why bundle finalization failed.
type FinalizeError struct {
	Stage   string
	Message string
}

func (e *FinalizeError) Error() string { return fmt.Sprintf("finalize %s: %s", e.Stage, e.Message) }
