package support

// Bundle format identity. Consumers reject an unknown MAJOR (SUPPORT-BUNDLE-SPEC §4).
const (
	BundleFormat        = "csb/1"
	CollectorEngineVer  = 1 // internal/support orchestration schema
	RedactionModelVer   = 1 // REDACTION-MODEL taxonomy/registry version
	ManifestName        = "manifest.json"
	CollectionErrorName = "collection-errors.json"
	RedactionReportName = "redaction-report.json"
)

// SupportBundleManifest is manifest.json — always the FIRST tar entry.
type SupportBundleManifest struct {
	Format      string          `json:"format"`
	BundleID    string          `json:"bundle_id"`
	CreatedAt   string          `json:"created_at"` // RFC3339 UTC
	GeneratedBy GeneratedBy     `json:"generated_by"`
	Node        NodeInfo        `json:"node"`
	Scope       ScopeInfo       `json:"scope"`
	CaseID      string          `json:"case_id,omitempty"`
	Redaction   RedactionInfo   `json:"redaction"`
	Sections    []SectionEntry  `json:"sections"`
	Integrity   IntegrityInfo   `json:"integrity"`
	Collection  CollectionStats `json:"collection"`
}

type GeneratedBy struct {
	Product                string    `json:"product"`
	Version                string    `json:"version"`
	Build                  BuildInfo `json:"build"`
	CollectorEngineVersion int       `json:"collector_engine_version"`
}

type BuildInfo struct {
	Commit  string `json:"commit,omitempty"`
	BuiltAt string `json:"built_at,omitempty"`
	Go      string `json:"go"`
}

type NodeInfo struct {
	NodeID    string `json:"node_id"`
	Role      string `json:"role"`
	Runtime   string `json:"runtime"`
	ClusterID string `json:"cluster_id,omitempty"`
}

type ScopeInfo struct {
	IncidentScope string `json:"incident_scope"`
	DebugLevel    int    `json:"debug_level"`
}

type RedactionInfo struct {
	ModelVersion int    `json:"model_version"`
	Profile      string `json:"profile"`
	FailClosed   bool   `json:"fail_closed"`
}

// SectionEntry is one manifest.sections[] row — present even for failed/skipped
// collectors so a reader can tell "not collected" from "collected empty".
type SectionEntry struct {
	ID               string        `json:"id"`
	Path             string        `json:"path"`
	Collector        string        `json:"collector"`
	CollectorVersion int           `json:"collector_version"`
	Owner            string        `json:"owner"`
	ClassMax         string        `json:"class_max"`
	SHA256           string        `json:"sha256,omitempty"`
	SizeBytes        int64         `json:"size_bytes"`
	StartedAt        string        `json:"started_at"`
	EndedAt          string        `json:"ended_at"`
	Status           SectionStatus `json:"status"`
	Truncated        bool          `json:"truncated"`
	Note             string        `json:"note,omitempty"`
}

type IntegrityInfo struct {
	ManifestSHA256 string `json:"manifest_sha256"` // hash of manifest with integrity fields zeroed
	BundleSHA256   string `json:"bundle_sha256"`   // hash of the whole tar
}

type CollectionStats struct {
	EngineStartedAt string `json:"engine_started_at"`
	EngineEndedAt   string `json:"engine_ended_at"`
	TotalCollectors int    `json:"total_collectors"`
	OK              int    `json:"ok"`
	Failed          int    `json:"failed"`
	Skipped         int    `json:"skipped"`
	ErrorCount      int    `json:"error_count"`
}

// CollectionError is one collection-errors.json entry. fatal is ALWAYS false for
// a collector; true only for an engine-level abort.
type CollectionError struct {
	Collector  string `json:"collector"`
	Phase      string `json:"phase"`       // preflight|execute|redact|assemble
	ErrorClass string `json:"error_class"` // timeout|panic|unavailable|permission|budget|runtime_unsupported
	Message    string `json:"message"`     // redacted
	Fatal      bool   `json:"fatal"`
}

// RedactionReport is redaction-report.json — counts only, never values (P4/P6).
type RedactionReport struct {
	ModelVersion int                      `json:"model_version"`
	Profile      string                   `json:"profile"`
	FailClosed   bool                     `json:"fail_closed"`
	Sections     []RedactionReportSection `json:"sections"`
	Totals       RedactionReportCounts    `json:"totals"`
}

type RedactionReportSection struct {
	ID       string `json:"id"`
	ClassMax string `json:"class_max"`
	Masked   int    `json:"masked"`
	Dropped  int    `json:"dropped"`
	Scrubbed int    `json:"scrubbed"` // free-form secret shapes redacted in kept strings
}

type RedactionReportCounts struct {
	Masked   int `json:"masked"`
	Dropped  int `json:"dropped"`
	Scrubbed int `json:"scrubbed"`
}

// RedactionPreviewName is the SERVER-SIDE-ONLY consent-preview file. It is
// written next to the manifest in the bundle dir but is NEVER added to the
// shareable tar and NEVER downloaded — it exists only so the pre-export consent
// endpoint can show the approver the retained free-form values. The bundled
// redaction-report.json stays counts-only (P4/P6); this is the sighted-gate
// companion that closes the "the human backstop is blind to the value it
// releases" gap without weakening the shareable report.
const RedactionPreviewName = "redaction-preview.json"

// RedactionPreview is redaction-preview.json — a BOUNDED sample of the INTERNAL
// free-form string values KEPT (post-scrub) in each section, surfaced to the
// approving admin only. Server-side; not part of the bundle.
type RedactionPreview struct {
	ModelVersion int                       `json:"model_version"`
	Sections     []RedactionPreviewSection `json:"sections"`
}

type RedactionPreviewSection struct {
	ID               string   `json:"id"`
	RetainedFreeForm []string `json:"retained_freeform"`
}
