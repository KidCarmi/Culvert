package main

// Security regression gate — 2026-11-13 review, finding A.
//
// recordDroppedNodeReenrollment (PR #1879) is the ONLY operator-facing signal
// that a node ID whose stored record was dropped as an unusable null entry has
// been re-enrolled under a fresh certificate whose PREDECESSOR can never reach
// the CRL. Its own doc comment promises the signal fires "loudly and once per
// enrollment".
//
// The webhook alert did not keep that promise. internal/alerts.Store.Dispatch
// suppresses a duplicate on `event + ":" + Detail` within dedupTTL (30 s), and
// the producer's Detail was a CONSTANT: every node's replacement shared one
// dedup key, so only the FIRST of a batch was delivered and the rest were
// dropped silently. The batch is the NORMAL shape, not an edge case — one
// corrupt cluster.json drops every null record it holds in a single
// normalizeClusterState pass (clusterStateRepair.NilNodes is a list), and the
// remediation is to re-issue tokens and let those nodes re-enroll together.
//
// recordExpiredNodeReenrollment escapes this only incidentally, by embedding
// per-node serials in its detail. These gates pin the dedup KEY of both
// producers, because the key is the part the producer controls; the suppression
// itself is Store.Dispatch's own tested behaviour, and the enrollAlertFire seam
// the other enrollment tests use bypasses it by construction, which is why the
// defect was invisible to them.

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// alertDedupKey is Store.Dispatch's suppression key (internal/alerts:
// dedupSuppressed(event + ":" + payload.Detail)). Two alerts that share it
// within dedupTTL are ONE delivery.
func alertDedupKey(p AlertPayload) string { return p.Event + ":" + p.Detail }

// enrollDroppedNode drives a full successful enrollment over a dropped record
// for nodeID and returns the alerts it produced.
func enrollDroppedNode(t *testing.T, nodeID string) []AlertPayload {
	t.Helper()
	loadStateWithNullNode(t, nodeID)
	alerts := enrollAlertCapture(t)
	token, err := globalClusterStore.GenerateToken("", "", "admin", time.Hour)
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	srv := &controlPlaneServer{}
	resp, err := srv.Enroll(context.Background(), enrollRequestJSON(t, token, nodeID))
	if err != nil {
		t.Fatalf("enrollment with a valid token must succeed: %v", err)
	}
	var er EnrollResponse
	if err := json.Unmarshal(resp, &er); err != nil || er.CertPEM == "" {
		t.Fatalf("enrollment response missing cert: err=%v resp=%s", err, resp)
	}
	return *alerts
}

// ── 1. regression: two nodes must not share one dedup key ───────────────────

func TestEnroll_DroppedRecordAlertsAreDistinctPerNode(t *testing.T) {
	first := enrollDroppedNode(t, "dp-dropped-a")
	second := enrollDroppedNode(t, "dp-dropped-b")

	if len(first) != 1 || len(second) != 1 {
		t.Fatalf("want one alert per enrollment, got %d and %d", len(first), len(second))
	}
	if got := first[0].Event; got != "cluster_node_reenrolled" {
		t.Fatalf("event = %q, want cluster_node_reenrolled", got)
	}
	if alertDedupKey(first[0]) == alertDedupKey(second[0]) {
		t.Fatalf("both nodes produce the SAME alert dedup key %q — within internal/alerts.dedupTTL "+
			"only ONE of them is delivered, so a batch of re-enrollments after a single corrupt "+
			"cluster.json silently loses every replacement after the first. The un-revocable "+
			"predecessor certificates of the rest are never reported.", alertDedupKey(first[0]))
	}
	// Positive: each detail names ITS OWN node and no other.
	if !strings.Contains(first[0].Detail, "dp-dropped-a") || strings.Contains(first[0].Detail, "dp-dropped-b") {
		t.Errorf("first alert detail must name dp-dropped-a and only it, got %q", first[0].Detail)
	}
	if !strings.Contains(second[0].Detail, "dp-dropped-b") || strings.Contains(second[0].Detail, "dp-dropped-a") {
		t.Errorf("second alert detail must name dp-dropped-b and only it, got %q", second[0].Detail)
	}
	// The irreversible fact must survive the rewording: an operator reading the
	// webhook alone has to learn the predecessor cannot be revoked.
	for _, p := range []AlertPayload{first[0], second[0]} {
		if !strings.Contains(p.Detail, "CRL") {
			t.Errorf("alert detail must still state the predecessor serial could not reach the CRL, got %q", p.Detail)
		}
		if p.Source != "cluster" {
			t.Errorf("alert source = %q, want cluster", p.Source)
		}
	}
	if first[0].Host != "dp-dropped-a" || second[0].Host != "dp-dropped-b" {
		t.Errorf("Host must keep naming the node: %q / %q", first[0].Host, second[0].Host)
	}
}

// ── 2. the audit entry keeps naming the node and the CRL loss ───────────────

// The audit trail was never deduped (auditAdd is a ring append), so this is a
// negative control on the fix: widening the detail must not disturb the entry
// the roster-side evidence is read from.
func TestEnroll_DroppedRecordAuditEntryStillIdentifiesTheNode(t *testing.T) {
	baseline := time.Now().UnixMilli()
	if got := enrollDroppedNode(t, "dp-dropped-audit"); len(got) != 1 {
		t.Fatalf("want one alert, got %d", len(got))
	}
	entry, ok := auditHasDroppedReenroll(t, baseline, "dp-dropped-audit")
	if !ok {
		t.Fatal("no cluster.node.reenroll-dropped audit entry for dp-dropped-audit")
	}
	if !strings.Contains(entry.Detail, "CRL") {
		t.Errorf("audit detail must state the predecessor serial could not reach the CRL, got %q", entry.Detail)
	}
	if !strings.Contains(entry.Detail, "dp-dropped-audit") {
		t.Errorf("audit detail must name the node so the entry is self-contained, got %q", entry.Detail)
	}
}

// ── 3. boundary / malformed: a hostile node ID cannot inject into the detail ─

// The node ID is CLIENT-SUPPLIED (EnrollRequest.NodeID). Promoting it into the
// detail promotes it into a logger.Printf argument, an audit record and a
// webhook body, so it must pass sanitizeLog BEFORE entering the detail
// (CWE-117).
//
// The assertion is on the SANITIZED SHAPE, not merely on the absence of raw
// control bytes, because %q alone satisfies the latter: it would render a
// newline as the two characters `\n` and the property check would pass with no
// sanitizer at all. sanitizeLog is the barrier the convention requires and the
// one CodeQL recognises (its leading strings.ReplaceAll), so the test pins its
// observable output — control bytes become `_` — and fails if %q is left to do
// the work on its own.
func TestRecordDroppedNodeReenrollment_SanitizesTheNodeIDInTheDetail(t *testing.T) {
	alerts := enrollAlertCapture(t)
	hostile := "dp-evil\nEnrollment: node \"dp-admin\" enrolled\r\x00"
	recordDroppedNodeReenrollment(hostile, "203.0.113.7")

	if len(*alerts) != 1 {
		t.Fatalf("want one alert, got %d", len(*alerts))
	}
	detail := (*alerts)[0].Detail
	if strings.ContainsAny(detail, "\n\r\x00") {
		t.Errorf("detail carries a raw control byte from the client-supplied node ID: %q", detail)
	}
	// sanitizeLog folds every C0 byte and DEL to '_', so the hostile ID must
	// appear with its newline replaced — never escaped-but-intact.
	if !strings.Contains(detail, "dp-evil_Enrollment") {
		t.Errorf("the node ID must reach the detail through sanitizeLog (newline folded to '_'), got %q", detail)
	}
	if strings.Contains(detail, `dp-evil\n`) {
		t.Errorf("the node ID reached the detail unsanitized and was merely %%q-escaped, got %q", detail)
	}
	// Still a usable, distinct dedup key rather than a collapsed constant.
	if alertDedupKey((*alerts)[0]) == "cluster_node_reenrolled:" {
		t.Error("sanitizing must not empty the detail")
	}
}

// ── 4. negative control: the expired-node producer stays distinct too ───────

// The two producers share the cluster_node_reenrolled event, so they share one
// dedup namespace. This pins that the expired path's key is still per-node (it
// embeds serials) and that neither producer can suppress the other.
func TestEnroll_ReenrollmentAlertKeysDoNotCollideAcrossProducers(t *testing.T) {
	dropped := enrollDroppedNode(t, "dp-dropped-x")

	alerts := enrollAlertCapture(t)
	prior := &EnrolledNode{NodeID: "dp-dropped-x", CertSerial: "AA11", CertExpiry: time.Now().Add(-time.Hour)}
	replacement := &EnrolledNode{NodeID: "dp-dropped-x", CertSerial: "BB22"}
	recordExpiredNodeReenrollment(context.Background(), prior, replacement)
	if len(*alerts) != 1 {
		t.Fatalf("want one expired-path alert, got %d", len(*alerts))
	}
	if alertDedupKey(dropped[0]) == alertDedupKey((*alerts)[0]) {
		t.Errorf("the dropped-record and expired-cert alerts for the same node share dedup key %q — "+
			"one would suppress the other inside dedupTTL", alertDedupKey(dropped[0]))
	}
}
