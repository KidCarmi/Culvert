package support

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/KidCarmi/Culvert/internal/redaction"
)

// BuildOptions parameterizes one bundle build. Clock and Nonce are injected so a
// build over identical frozen state is byte-deterministic (TestBundleDeterministic).
type BuildOptions struct {
	Version       string
	GoVersion     string
	BuildCommit   string
	BuildAt       string
	Runtime       RuntimeInfo
	ClusterID     string
	Level         DebugLevel
	IncidentScope string
	// IncludeCollectors, when non-empty, restricts the bundle to collectors whose
	// ID is present (an incident-scoped collection). Empty/nil = every collector
	// (the "standard" scope). The catalog of scope→IDs lives in the owning package;
	// the engine stays generic. Level gating still applies within the scope.
	IncludeCollectors map[string]bool
	Profile           string
	CaseID            string
	Nonce             string
	Clock             func() time.Time
	Salt              []byte // optional; deterministic masking for tests
}

// BuildResult is a finished bundle: its id, manifest, and the gzipped-tar bytes.
type BuildResult struct {
	BundleID     string
	Manifest     SupportBundleManifest
	Report       RedactionReport // counts-only redaction report (also packaged in the tar)
	TarGz        []byte
	BundleSHA256 string
}

// Runner assembles a bundle from the registered collectors.
type Runner struct{}

// NewRunner returns a runner over the process collector registry.
func NewRunner() *Runner { return &Runner{} }

type tarEntry struct {
	name string
	body []byte
}

// Build runs every eligible collector and assembles a csb/1 bundle. It never
// returns an error for a collector failure (that becomes a failed section +
// collection-errors entry); it errors only on an engine-level assembly failure.
func (rn *Runner) Build(ctx context.Context, opts BuildOptions) (*BuildResult, error) {
	clock := opts.Clock
	if clock == nil {
		clock = time.Now
	}
	profile := opts.Profile
	if profile == "" {
		profile = "default"
	}
	scope := opts.IncidentScope
	if scope == "" {
		scope = "standard"
	}
	engineStart := clock().UTC()
	createdAt := engineStart.Format(time.RFC3339)

	var base redaction.Redactor
	if len(opts.Salt) > 0 {
		base = redaction.NewWithSalt(opts.Salt)
	} else {
		base = redaction.New()
	}

	var (
		sections   []SectionEntry
		reportSecs []RedactionReportSection
		errs       = []CollectionError{}
		packed     []tarEntry
		stats      CollectionStats
	)

	for _, c := range Collectors() {
		m := c.Meta()
		stats.TotalCollectors++
		startAt := clock().UTC().Format(time.RFC3339)
		entry := SectionEntry{
			ID: m.ID, Path: m.Path, Collector: m.ID, CollectorVersion: m.SchemaVersion,
			Owner: m.Owner, StartedAt: startAt, ClassMax: redaction.ClassPublic.String(),
		}

		if len(opts.IncludeCollectors) > 0 && !opts.IncludeCollectors[m.ID] {
			entry.Status = StatusSkipped
			entry.Note = "gated:scope=" + scope
			entry.EndedAt = clock().UTC().Format(time.RFC3339)
			sections = append(sections, entry)
			stats.Skipped++
			continue
		}

		if opts.Level < m.MinLevel {
			entry.Status = StatusSkipped
			entry.Note = fmt.Sprintf("gated:level<%d", m.MinLevel)
			entry.EndedAt = clock().UTC().Format(time.RFC3339)
			sections = append(sections, entry)
			stats.Skipped++
			continue
		}

		cr := &countingRedactor{base: base}
		sk := &sectionSink{budget: m.ByteBudget}
		in := CollectInput{Level: opts.Level, Redactor: cr, Runtime: opts.Runtime, Clock: clock}
		res, errClass := runOne(ctx, c, in, sk, m.Timeout)
		entry.EndedAt = clock().UTC().Format(time.RFC3339)
		entry.Truncated = res.Truncated || sk.truncated
		entry.Note = res.Note

		switch {
		case errClass != "":
			entry.Status = StatusFailed
			errs = append(errs, CollectionError{
				Collector: m.ID, Phase: "execute", ErrorClass: errClass,
				Message: "collector " + m.ID + " " + errClass, Fatal: false,
			})
			stats.Failed++
		case res.Status == StatusFailed || res.Status == StatusUnavailable:
			entry.Status = res.Status
			if res.Status == StatusFailed {
				stats.Failed++
			}
		case !sk.wrote:
			entry.Status = StatusFailed
			errs = append(errs, CollectionError{
				Collector: m.ID, Phase: "execute", ErrorClass: "budget",
				Message: "collector " + m.ID + " wrote no section", Fatal: false,
			})
			stats.Failed++
		default:
			classMax := cr.classMax
			if res.ClassMax > classMax {
				classMax = res.ClassMax
			}
			if classMax > m.MaxClass {
				// Defense-in-depth: a section exceeding its declared ceiling is
				// dropped + errored, never emitted (REDACTION-MODEL §9).
				entry.Status = StatusFailed
				errs = append(errs, CollectionError{
					Collector: m.ID, Phase: "redact", ErrorClass: "permission",
					Message: fmt.Sprintf("section %s class %s exceeds ceiling %s", m.ID, classMax, m.MaxClass),
					Fatal:   false,
				})
				stats.Failed++
				break
			}
			sum := sha256.Sum256(sk.body)
			entry.SHA256 = hex.EncodeToString(sum[:])
			entry.SizeBytes = int64(len(sk.body))
			entry.ClassMax = classMax.String()
			if entry.Status = res.Status; entry.Status == "" {
				entry.Status = StatusOK
			}
			packed = append(packed, tarEntry{name: m.Path, body: sk.body})
			reportSecs = append(reportSecs, RedactionReportSection{
				ID: m.ID, ClassMax: classMax.String(), Masked: cr.masked, Dropped: cr.dropped, Scrubbed: cr.scrubbed,
			})
			stats.OK++
		}
		sections = append(sections, entry)
	}

	stats.EngineStartedAt = createdAt
	stats.EngineEndedAt = clock().UTC().Format(time.RFC3339)
	stats.ErrorCount = len(errs)

	bundleID := makeBundleID(opts.Runtime.NodeID, createdAt, opts.Nonce)

	report := RedactionReport{
		ModelVersion: RedactionModelVer, Profile: profile, FailClosed: true,
		Sections: reportSecs, Totals: totalCounts(reportSecs),
	}
	reportBytes, _ := json.MarshalIndent(report, "", "  ")
	errBytes, _ := json.MarshalIndent(errs, "", "  ")

	man := SupportBundleManifest{
		Format:    BundleFormat,
		BundleID:  bundleID,
		CreatedAt: createdAt,
		GeneratedBy: GeneratedBy{
			Product: "culvert", Version: opts.Version,
			Build:                  BuildInfo{Commit: opts.BuildCommit, BuiltAt: opts.BuildAt, Go: opts.GoVersion},
			CollectorEngineVersion: CollectorEngineVer,
		},
		Node: NodeInfo{
			NodeID: opts.Runtime.NodeID, Role: opts.Runtime.Role,
			Runtime: opts.Runtime.Runtime, ClusterID: opts.ClusterID,
		},
		Scope:      ScopeInfo{IncidentScope: scope, DebugLevel: int(opts.Level)},
		CaseID:     opts.CaseID,
		Redaction:  RedactionInfo{ModelVersion: RedactionModelVer, Profile: profile, FailClosed: true},
		Sections:   sections,
		Collection: stats,
	}
	// manifest_sha256 is over the manifest with both integrity fields empty.
	man.Integrity = IntegrityInfo{}
	preHash, _ := json.MarshalIndent(man, "", "  ")
	ms := sha256.Sum256(preHash)
	man.Integrity.ManifestSHA256 = hex.EncodeToString(ms[:])
	manifestBytes, _ := json.MarshalIndent(man, "", "  ")

	// Deterministic entry order: manifest first, then the required top-level
	// files, then sections (already collector-ID-ascending).
	entries := []tarEntry{
		{name: ManifestName, body: manifestBytes},
		{name: RedactionReportName, body: reportBytes},
		{name: CollectionErrorName, body: errBytes},
	}
	entries = append(entries, packed...)

	tgz, err := writeTarGz(entries, engineStart)
	if err != nil {
		return nil, fmt.Errorf("assemble bundle: %w", err)
	}
	bs := sha256.Sum256(tgz)
	man.Integrity.BundleSHA256 = hex.EncodeToString(bs[:])

	return &BuildResult{
		BundleID: bundleID, Manifest: man, Report: report, TarGz: tgz,
		BundleSHA256: man.Integrity.BundleSHA256,
	}, nil
}

// runOne executes one collector under a timeout with panic isolation. errClass is
// "" on a clean return, else "panic"/"timeout".
func runOne(parent context.Context, c Collector, in CollectInput, sk SectionSink, timeout time.Duration) (Result, string) {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()

	type out struct {
		res      Result
		panicMsg string
	}
	ch := make(chan out, 1)
	go func() {
		defer func() {
			if rec := recover(); rec != nil {
				ch <- out{res: Result{Status: StatusFailed}, panicMsg: fmt.Sprintf("%v", rec)}
			}
		}()
		ch <- out{res: c.Collect(ctx, in, sk)}
	}()

	select {
	case o := <-ch:
		if o.panicMsg != "" {
			return o.res, "panic"
		}
		return o.res, ""
	case <-ctx.Done():
		return Result{Status: StatusFailed, Note: "timeout"}, "timeout"
	}
}

// sectionSink buffers one section, enforcing the byte budget and marshaling
// deterministically (json.Marshal sorts map keys; redacted values are maps).
type sectionSink struct {
	budget    int64
	body      []byte
	truncated bool
	wrote     bool
}

func (s *sectionSink) WriteJSON(v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	if s.budget > 0 && int64(len(b)) > s.budget {
		s.truncated = true
		b, _ = json.MarshalIndent(map[string]any{
			"truncated": true, "reason": "section exceeded byte budget", "budget_bytes": s.budget,
		}, "", "  ")
	}
	s.body = b
	s.wrote = true
	return nil
}

// countingRedactor wraps the base redactor and tallies masked/dropped/scrubbed/
// class_max across a single section, feeding the manifest entry + redaction report.
type countingRedactor struct {
	base                      redaction.Redactor
	masked, dropped, scrubbed int
	classMax                  redaction.DataClass
}

func (c *countingRedactor) Struct(v any) any {
	r := c.base.Classify(v)
	c.tally(r)
	return r.Value
}

func (c *countingRedactor) Classify(v any) redaction.Result {
	r := c.base.Classify(v)
	c.tally(r)
	return r
}

func (c *countingRedactor) tally(r redaction.Result) {
	c.masked += r.Masked
	c.dropped += r.Dropped
	c.scrubbed += r.Scrubbed
	if r.ClassMax > c.classMax {
		c.classMax = r.ClassMax
	}
}

func totalCounts(secs []RedactionReportSection) RedactionReportCounts {
	var t RedactionReportCounts
	for _, s := range secs {
		t.Masked += s.Masked
		t.Dropped += s.Dropped
		t.Scrubbed += s.Scrubbed
	}
	return t
}

// makeBundleID is deterministic: base32(sha256(node|created_at|nonce))[:26],
// ULID-shaped and collision-resistant; the nonce separates concurrent requests.
func makeBundleID(nodeID, createdAt, nonce string) string {
	h := sha256.Sum256([]byte(nodeID + "|" + createdAt + "|" + nonce))
	enc := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(h[:])
	return "csb_" + strings.ToLower(enc)[:26]
}

// writeTarGz assembles a deterministic gzipped tar: fixed entry order, fixed
// per-entry ModTime, no gzip name/comment header — byte-identical under a fixed
// clock over identical input.
func writeTarGz(entries []tarEntry, modTime time.Time) ([]byte, error) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	mt := modTime.UTC().Truncate(time.Second)
	for _, e := range entries {
		hdr := &tar.Header{
			Name: e.name, Mode: 0o600, Size: int64(len(e.body)),
			ModTime: mt, Typeflag: tar.TypeReg,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, err
		}
		if _, err := tw.Write(e.body); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
