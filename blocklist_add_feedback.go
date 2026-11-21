package main

import (
	"fmt"
	"strings"
)

// Operator feedback for POST /api/blocklist.
//
// The handler knew more than it told the caller: an over-length entry was
// dropped with only a log line, a repeat of an existing admin entry was a silent
// no-op, and an entry that can never equal a destination hostname (a pasted URL,
// a host:port, a trailing dot, a Unicode IDN) was stored and listed as if it
// were enforcing — while the admin UI reported the number of lines it SENT.
//
// This file only DESCRIBES the outcome. What is accepted, stored and matched is
// unchanged; the fields are additive on a response whose schema is an open object.

// blocklistAddNoteCap bounds the per-entry detail so the response cannot grow
// with a bulk import; the counts stay exact.
const blocklistAddNoteCap = 50

// blocklistEntryNote is one entry the operator should look at, with the reason.
type blocklistEntryNote struct {
	Host   string `json:"host"`
	Reason string `json:"reason"`
}

// blocklistAddOutcome accumulates the feedback for one add request.
type blocklistAddOutcome struct {
	skipped      []blocklistEntryNote
	skippedCount int
}

// skip records an entry the handler dropped without storing it.
func (o *blocklistAddOutcome) skip(host, reason string) {
	o.skippedCount++
	if len(o.skipped) < blocklistAddNoteCap {
		o.skipped = append(o.skipped, blocklistEntryNote{Host: host, Reason: reason})
	}
}

// response builds the POST /api/blocklist body. `added` keeps its existing
// meaning (net new admin entries, per Store.AddManualBulk); the rest is new.
func (o *blocklistAddOutcome) response(valid []string, added int) map[string]any {
	distinct := make(map[string]struct{}, len(valid))
	var warnings []blocklistEntryNote
	warningCount := 0
	for _, h := range valid {
		// Same per-entry key AddManualBulk derives, so "unchanged" is exactly
		// the distinct entries that call did not newly attribute.
		key := strings.ToLower(strings.TrimSpace(h))
		if _, dup := distinct[key]; dup {
			continue
		}
		distinct[key] = struct{}{}
		if reason := blocklistEntryMatchWarning(key); reason != "" {
			warningCount++
			if len(warnings) < blocklistAddNoteCap {
				warnings = append(warnings, blocklistEntryNote{Host: key, Reason: reason})
			}
		}
	}
	unchanged := len(distinct) - added
	if unchanged < 0 { // a concurrent removal between the add and this count
		unchanged = 0
	}
	resp := map[string]any{
		"added":         added,
		"unchanged":     unchanged,
		"skipped_count": o.skippedCount,
		"warning_count": warningCount,
	}
	if len(o.skipped) > 0 {
		resp["skipped"] = o.skipped
	}
	if len(warnings) > 0 {
		resp["warnings"] = warnings
	}
	return resp
}

// blocklistEntryMatchWarning reports why a stored entry is not expected to
// match any destination, or "" when it is an ordinary hostname pattern.
//
// The blocklist is probed with the request's bare, normalized destination host
// (bareDestHost strips the port in the proxy; Store.IsBlocked applies
// hostutil.NormalizeHost) against keys stored lowercased-and-trimmed only. An
// entry is therefore inert whenever it carries something that value never
// contains. The checks are deliberately conservative: a bare IPv6 literal is
// not a host:port and is not flagged.
func blocklistEntryMatchWarning(entry string) string {
	pattern := strings.TrimPrefix(entry, "*.")
	switch {
	case strings.Contains(pattern, "/"):
		return "looks like a URL or path; the blocklist matches the destination hostname only (enter example.com)"
	case strings.ContainsAny(pattern, " \t?#@"):
		return "contains characters a destination hostname never has; enter the bare hostname"
	case bareDestHost(pattern) != pattern:
		return fmt.Sprintf("includes a port; the port is removed before matching (enter %s)", bareDestHost(pattern))
	}
	if canonical := normalizeHost(pattern); canonical != pattern {
		return fmt.Sprintf("is not in canonical form; destinations are matched as %s", canonical)
	}
	return ""
}
