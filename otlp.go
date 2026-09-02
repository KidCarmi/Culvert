package main

// otlp.go — package-main glue for OTLP/HTTP export, moved to internal/otlp
// (post-ADR-0002 recorded extraction). The engine owns the transport (push
// loops, SSRF-guarded client, endpoint validation) and the OTLP JSON
// schema; main owns WHAT gets exported — the snapshot builders below read
// the culvert_* stat singletons and are injected into the metrics exporter
// at construction. Span recording (proxy.go) goes through the aliases.
//
// Configuration:
//   -otlp-endpoint http://otel-collector:4318    (OTLP/HTTP receiver)
//   config.yaml:  otlp_endpoint: "http://otel-collector:4318"

import (
	"fmt"
	"sync/atomic"
	"time"

	"github.com/KidCarmi/Culvert/internal/otlp"
	"github.com/KidCarmi/Culvert/internal/secscan"
)

// OTLPExporter pushes metrics to an OTLP/HTTP endpoint (engine type is
// otlp.MetricsExporter).
type OTLPExporter = otlp.MetricsExporter

// OTLPSpanExporter collects and pushes request spans (engine type is
// otlp.SpanExporter).
type OTLPSpanExporter = otlp.SpanExporter

// SpanRecord holds the per-request span data (engine type is
// otlp.SpanRecord).
type SpanRecord = otlp.SpanRecord

var (
	globalOTLP       = otlp.NewMetrics(culvertMetricsSnapshot)
	globalOTLPTraces = otlp.NewSpans()
)

// parseTraceparent extracts trace-id and span-id from a W3C Traceparent
// header value. Wrapper function (not a func var) — called per request on
// the proxy telemetry path.
func parseTraceparent(tp string) (traceID, spanID string) { return otlp.ParseTraceparent(tp) }

// culvertMetricsSnapshot builds the full culvert_* metric set, stamped with
// now (UnixNano string). This is the injected snapshot source for
// globalOTLP — it reads main's stat singletons, which is exactly why it
// lives here and not in the engine.
func culvertMetricsSnapshot(now string) []otlp.Metric {
	metrics := otlpCounterMetrics(now)
	metrics = append(metrics, otlpGaugeMetrics(now)...)
	metrics = append(metrics, otlpHistogramMetric(now))
	metrics = append(metrics, otlpRuleMetrics(now)...)
	return metrics
}

func otlpCounterMetrics(now string) []otlp.Metric {
	scanCounters := secscan.Counters()
	counters := []struct {
		name string
		desc string
		val  int64
	}{
		{"culvert.requests.total", "Total proxy requests", atomic.LoadInt64(&statTotal)},
		{"culvert.requests.blocked", "Total blocked requests", atomic.LoadInt64(&statBlocked)},
		{"culvert.requests.auth_fail", "Total auth failures", atomic.LoadInt64(&statAuthFail)},
		{"culvert.requests.file_blocked", "File extension blocks", atomic.LoadInt64(&statFileBlocked)},
		{"culvert.requests.dpi_blocked", "DPI content blocks", atomic.LoadInt64(&statDPIBlocked)},
		{"culvert.requests.clamav_blocked", "ClamAV blocks", scanCounters.ClamBlocked},
		{"culvert.requests.yara_blocked", "YARA blocks", scanCounters.YARABlocked},
		{"culvert.requests.threat_feed_blocked", "Threat feed blocks", scanCounters.ThreatFeedBlocked},
		{"culvert.bytes.sent", "Bytes sent upstream", atomic.LoadInt64(&statBytesSent)},
		{"culvert.bytes.recv", "Bytes received", atomic.LoadInt64(&statBytesRecv)},
	}
	metrics := make([]otlp.Metric, 0, len(counters))
	for _, c := range counters {
		v := c.val
		metrics = append(metrics, otlp.Metric{
			Name:        c.name,
			Description: c.desc,
			Sum: &otlp.Sum{
				AggregationTemporality: 2, // cumulative
				IsMonotonic:            true,
				DataPoints: []otlp.NumberDataPoint{{
					TimeUnixNano: now,
					AsInt:        &v,
				}},
			},
		})
	}
	return metrics
}

func otlpGaugeMetrics(now string) []otlp.Metric {
	uptimeSec := time.Since(startTime).Seconds()
	feedEntries, _, _ := globalThreatFeed.Stats()
	_, _, cacheSize := globalSecScanner.CacheStats()
	gauges := []struct {
		name string
		desc string
		val  float64
	}{
		{"culvert.uptime", "Proxy uptime in seconds", uptimeSec},
		{"culvert.blocklist.size", "Blocked domains count", float64(bl.Count())},
		{"culvert.rate_limit.rpm", "Configured rate limit RPM", float64(rl.Limit())},
		{"culvert.threat_feed.entries", "Threat feed entries", float64(feedEntries)},
		{"culvert.scan_cache.size", "Scan cache entries", float64(cacheSize)},
	}
	metrics := make([]otlp.Metric, 0, len(gauges))
	for _, g := range gauges {
		v := g.val
		metrics = append(metrics, otlp.Metric{
			Name:        g.name,
			Description: g.desc,
			Unit:        "1",
			Gauge: &otlp.Gauge{
				DataPoints: []otlp.NumberDataPoint{{
					TimeUnixNano: now,
					AsDouble:     &v,
				}},
			},
		})
	}
	return metrics
}

func otlpHistogramMetric(now string) otlp.Metric {
	// One snapshot folds the sharded counters into per-bucket counts, the
	// observation count and the summed seconds (metrics.go). Reading the three
	// through a single snapshot is also what keeps Count consistent with
	// BucketCounts — they now come from the same fold.
	counts, total, histSum := latencyHist.snapshot()
	bucketCounts := make([]string, len(counts))
	for i, c := range counts {
		bucketCounts[i] = fmt.Sprintf("%d", c)
	}
	return otlp.Metric{
		Name:        "culvert.request.duration",
		Description: "Request latency",
		Unit:        "s",
		Histogram: &otlp.Hist{
			AggregationTemporality: 2,
			DataPoints: []otlp.HistDataPoint{{
				TimeUnixNano:   now,
				Count:          total,
				Sum:            histSum,
				BucketCounts:   bucketCounts,
				ExplicitBounds: latencyHist.buckets,
			}},
		},
	}
}

func otlpRuleMetrics(now string) []otlp.Metric {
	cur := ruleMet.view()
	metrics := make([]otlp.Metric, 0, len(cur.order))
	for _, name := range cur.order {
		ctr := cur.hits[name]
		v := atomic.LoadInt64(ctr)
		metrics = append(metrics, otlp.Metric{
			Name:        "culvert.policy.rule_hits",
			Description: "Per-rule hit count",
			Sum: &otlp.Sum{
				AggregationTemporality: 2,
				IsMonotonic:            true,
				DataPoints: []otlp.NumberDataPoint{{
					TimeUnixNano: now,
					AsInt:        &v,
					Attributes: []otlp.KeyValue{{
						Key:   "rule",
						Value: otlp.AnyValue{StringValue: name},
					}},
				}},
			},
		})
	}
	return metrics
}
