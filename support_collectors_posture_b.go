package main

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/KidCarmi/Culvert/internal/redaction"
	"github.com/KidCarmi/Culvert/internal/secscan"
	"github.com/KidCarmi/Culvert/internal/support"
)

// M2 breadth collectors, part 2 (upstream, cdr, scan). Same fail-closed pattern:
// a purpose-built redact:-tagged section fed from an existing side-effect-free,
// NETWORK-FREE accessor. Deliberately avoids the credential/dial hazards:
//   - upstream: redacted List() (no inline proxy creds), never Entries().
//   - cdr: cached health snapshot + atomic gauges, never the live client.Health() dial.
//   - scan: pure Enabled()/BodyScanEnabled()/CacheStats()/Counters(), never the
//     on-cache-miss ClamAV Ping (ClamAVStatus/ClamAVVersion).

const supportMaxUpstreamProxies = 100

// ── upstream pool ────────────────────────────────────────────────────────────

type upstreamProxyStatus struct {
	URL      string `json:"url" redact:"internal"` // redacted by List() — no inline creds
	Healthy  bool   `json:"healthy" redact:"public"`
	Circuit  string `json:"circuit" redact:"public"`
	Failures int64  `json:"failures" redact:"public"`
}

type upstreamSection struct {
	Enabled bool                  `json:"enabled" redact:"public"`
	Count   int                   `json:"count" redact:"public"`
	Proxies []upstreamProxyStatus `json:"proxies" redact:"internal"`
}

type upstreamCollector struct{}

func (upstreamCollector) Meta() support.CollectorMeta {
	return support.CollectorMeta{
		ID: "upstream", Path: "sections/upstream.json", Owner: "core", SchemaVersion: 1,
		Description: "Upstream proxy pool + circuit-breaker posture (redacted URLs, no creds)", Timeout: 2 * time.Second,
		ByteBudget: 32 << 10, Mandatory: false, MinLevel: support.L1,
		MaxClass: redaction.ClassInternal, Sensitivity: redaction.ClassInternal,
	}
}

func (upstreamCollector) Collect(_ context.Context, in support.CollectInput, sink support.SectionSink) support.Result {
	list := upstreamPool.List() // redacted (host:port only), in-memory, no dial
	sec := upstreamSection{Enabled: upstreamPool.Enabled(), Count: len(list)}
	if len(list) > supportMaxUpstreamProxies {
		list = list[:supportMaxUpstreamProxies]
	}
	sec.Proxies = make([]upstreamProxyStatus, 0, len(list))
	for i := range list {
		sec.Proxies = append(sec.Proxies, upstreamProxyStatus{
			URL: list[i].URL, Healthy: list[i].Healthy, Circuit: list[i].Circuit, Failures: list[i].Failures,
		})
	}
	return classifyAndWriteSection(in, sink, sec)
}

// ── cdr / Sluice ─────────────────────────────────────────────────────────────

type cdrSection struct {
	Enabled         bool   `json:"enabled" redact:"public"`
	Endpoint        string `json:"endpoint,omitempty" redact:"internal"`
	FailMode        string `json:"fail_mode,omitempty" redact:"internal"`
	InstanceCount   int    `json:"instance_count" redact:"public"`
	PolicyCount     int    `json:"policy_count" redact:"public"`
	HealthKnown     bool   `json:"health_known" redact:"public"` // a cached health snapshot exists
	InstanceHealthy bool   `json:"instance_healthy" redact:"internal"`
	QueueDepth      int64  `json:"queue_depth" redact:"internal"`
}

type cdrCollector struct{}

func (cdrCollector) Meta() support.CollectorMeta {
	return support.CollectorMeta{
		ID: "cdr", Path: "sections/cdr.json", Owner: "cdr", SchemaVersion: 1,
		Description: "CDR (Sluice) posture: enabled, instances, policies, cached health (no live dial)", Timeout: 2 * time.Second,
		ByteBudget: 16 << 10, Mandatory: false, MinLevel: support.L1,
		MaxClass: redaction.ClassInternal, Sensitivity: redaction.ClassInternal,
	}
}

func (cdrCollector) Collect(_ context.Context, in support.CollectInput, sink support.SectionSink) support.Result {
	cfg := cdrActiveConfig()
	sec := cdrSection{
		Enabled:         cfg.Enabled,
		Endpoint:        cfg.Endpoint,
		FailMode:        cfg.FailMode,
		InstanceCount:   len(cdrInstances.List()),
		PolicyCount:     len(cdrPolicyStore.List()),
		HealthKnown:     cdrGetHealthSnapshot() != nil, // cached only; nil = no data, never dials
		InstanceHealthy: atomic.LoadInt64(&statCDRInstanceHealthy) == 1,
		QueueDepth:      atomic.LoadInt64(&statCDRQueueDepth),
	}
	res := in.Redactor.Classify(sec)
	if err := sink.WriteJSON(res.Value); err != nil {
		return support.Result{Status: support.StatusFailed, Note: "write"}
	}
	return support.Result{Status: support.StatusOK, ClassMax: res.ClassMax}
}

// ── scan / DPI ───────────────────────────────────────────────────────────────

type scanSection struct {
	ScanMode          string `json:"scan_mode" redact:"public"`           // local | remote
	RemoteScanEnabled bool   `json:"remote_scan_enabled" redact:"public"` // sidecar scanning active
	ScannerEnabled    bool   `json:"scanner_enabled" redact:"public"`     // LOCAL scanner initialized
	BodyScanEnabled   bool   `json:"body_scan_enabled" redact:"public"`
	DPIEnabled        bool   `json:"dpi_enabled" redact:"public"`
	DPIPatternCount   int    `json:"dpi_pattern_count" redact:"public"`
	YARAEnabled       bool   `json:"yara_enabled" redact:"public"`
	YARARuleCount     int    `json:"yara_rule_count" redact:"public"`
	HashCacheReady    bool   `json:"hash_cache_ready" redact:"public"`
	HashCacheSize     int    `json:"hash_cache_size" redact:"public"`
	HashCacheHits     int64  `json:"hash_cache_hits" redact:"public"`
	HashCacheMisses   int64  `json:"hash_cache_misses" redact:"public"`
	DPIBlocked        int64  `json:"dpi_blocked" redact:"internal"`
	ClamBlocked       int64  `json:"clam_blocked" redact:"internal"`
	YARABlocked       int64  `json:"yara_blocked" redact:"internal"`
	ThreatFeedBlocked int64  `json:"threat_feed_blocked" redact:"internal"`
	ScanTimeout       int64  `json:"scan_timeout" redact:"internal"`
	ScanSkipped       int64  `json:"scan_skipped" redact:"internal"`
	ScanError         int64  `json:"scan_error" redact:"internal"`
	ScanOnError       string `json:"scan_on_error" redact:"internal"`
}

type scanCollector struct{}

func (scanCollector) Meta() support.CollectorMeta {
	return support.CollectorMeta{
		ID: "scan", Path: "sections/scan.json", Owner: "security", SchemaVersion: 1,
		Description: "Content-scan posture: DPI/YARA/ClamAV wiring + hash-cache + scan counters (no ClamAV dial)", Timeout: 2 * time.Second,
		ByteBudget: 16 << 10, Mandatory: false, MinLevel: support.L1,
		MaxClass: redaction.ClassInternal, Sensitivity: redaction.ClassInternal,
	}
}

func (scanCollector) Collect(_ context.Context, in support.CollectInput, sink support.SectionSink) support.Result {
	hits, misses, size := globalSecScanner.CacheStats()
	c := secscan.Counters()
	// Remote (sidecar) scan mode leaves the LOCAL scanner off, so report the mode
	// + remote-enabled explicitly — otherwise a remote deployment misreads as
	// "scanning disabled". Uses only the pure Enabled() probe (no sidecar dial).
	remote := globalRemoteScanner.Enabled()
	mode := "local"
	if remote {
		mode = "remote"
	}
	sec := scanSection{
		ScanMode:          mode,
		RemoteScanEnabled: remote,
		ScannerEnabled:    globalSecScanner.Enabled(),
		BodyScanEnabled:   globalSecScanner.BodyScanEnabled(),
		DPIEnabled:        dpiScanner.Enabled(),
		DPIPatternCount:   len(dpiScanner.List()),
		// Honor the runtime YARA toggle, not just "rules loaded" (production
		// adapter is yaraGetEnabled() && rs.Enabled()); rule count stays raw.
		YARAEnabled:       yaraGetEnabled() && globalYARA.Enabled(),
		YARARuleCount:     globalYARA.Count(),
		HashCacheReady:    globalSecScanner.CacheReady(),
		HashCacheSize:     size,
		HashCacheHits:     hits,
		HashCacheMisses:   misses,
		DPIBlocked:        atomic.LoadInt64(&statDPIBlocked),
		ClamBlocked:       c.ClamBlocked,
		YARABlocked:       c.YARABlocked,
		ThreatFeedBlocked: c.ThreatFeedBlocked,
		ScanTimeout:       c.ScanTimeout,
		ScanSkipped:       c.ScanSkipped,
		ScanError:         c.ScanError,
		ScanOnError:       secscanGetOnScanError(),
	}
	res := in.Redactor.Classify(sec)
	if err := sink.WriteJSON(res.Value); err != nil {
		return support.Result{Status: support.StatusFailed, Note: "write"}
	}
	return support.Result{Status: support.StatusOK, ClassMax: res.ClassMax}
}

func init() {
	support.Register(upstreamCollector{})
	support.Register(cdrCollector{})
	support.Register(scanCollector{})
}
