package session

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// CHAOS-66 — the session revocation plane.
//
// A Culvert session cookie is self-contained and is trusted on its HMAC alone,
// so the revocation list is the ONLY way to withdraw authority from a session
// that is already issued, and the window it would otherwise run to is up to
// maxTTL (7 days). Every gate below is a statement about that one property.
//
// The DEFECT gates were each verified failing against the pre-fix tree.

// chaosRevocationsPath points persistence at a fresh temp file for the test
// and returns it.
func chaosRevocationsPath(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "revocations.json")
	withRevocationsPath(t, path)
	return path
}

// DEFECT (persistence). RevokeUser wrote only to the in-memory `users` map,
// and SaveRevocations exported only `tokens` — so deleting an account revoked
// its live sessions until the process exited and no longer.
func TestChaos66_UserRevocationSurvivesARestart(t *testing.T) {
	chaosRevocationsPath(t)

	before := NewRevocationList()
	before.Revoke("tok-a", time.Now().Add(time.Hour))
	before.RevokeUser("alice")
	if err := before.SaveRevocations(); err != nil {
		t.Fatalf("save: %v", err)
	}

	after := NewRevocationList()
	if err := after.LoadRevocations(); err != nil {
		t.Fatalf("load: %v", err)
	}
	if !after.IsRevoked("tok-a") {
		t.Error("token revocation did not survive the restart")
	}
	if !after.IsUserRevoked("alice") {
		t.Error("user revocation did not survive the restart: a deleted account's live session works again")
	}
}

// DEFECT (gossip). ExportRevocations walked `tokens` only, so a deleted
// account was revoked on the one node that served the DELETE and nowhere else.
func TestChaos66_UserRevocationCrossesTheGossip(t *testing.T) {
	src := NewRevocationList()
	src.Revoke("tok-b", time.Now().Add(time.Hour))
	src.RevokeUser("bob")

	dst := NewRevocationList()
	if added := dst.MergeRevocations(src.ExportRevocations()); added != 2 {
		t.Errorf("added = %d, want 2 (one token + one user)", added)
	}
	if !dst.IsRevoked("tok-b") {
		t.Error("token revocation did not cross the gossip")
	}
	if !dst.IsUserRevoked("bob") {
		t.Error("user revocation did not cross the gossip: other nodes keep honouring the deleted account's cookie")
	}
}

// SECURITY INVARIANT. The aggregator (controlplane.go MergedExcluding)
// de-duplicates the fleet-wide merge on Token alone. If user entries shared a
// Token value, every user revocation in the cluster would collapse into one
// and the fleet would learn about a single deleted account.
func TestChaos66_UserEntriesHaveDistinctTokens(t *testing.T) {
	r := NewRevocationList()
	r.RevokeUser("alice")
	r.RevokeUser("bob")
	r.RevokeUser("carol")

	seen := map[string]bool{}
	users := 0
	for _, e := range r.ExportRevocations() {
		if e.User == "" {
			continue
		}
		users++
		if e.Token == "" {
			t.Fatalf("user entry for %q carries an empty Token — the aggregator dedups on Token and would collapse every user revocation into one", e.User)
		}
		if seen[e.Token] {
			t.Fatalf("duplicate Token %q across user entries", e.Token)
		}
		seen[e.Token] = true
	}
	if users != 3 {
		t.Fatalf("exported %d user entries, want 3", users)
	}
}

// SECURITY INVARIANT. The user-entry Token must be unable to match a real
// cookie payload, in BOTH directions: a downgraded node files it under
// tokens[] and must never match a live session with it, and MergeRevocations
// classifies by the prefix and must never swallow a genuine token revocation.
func TestChaos66_UserRevocationTokenCannotCollideWithACookiePayload(t *testing.T) {
	// A real token is the RawURLEncoding of a Session payload; that alphabet
	// is [A-Za-z0-9-_], so a prefix containing any other byte is unreachable.
	const b64Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	if !strings.ContainsFunc(userRevocationTokenPrefix, func(r rune) bool {
		return !strings.ContainsRune(b64Alphabet, r)
	}) {
		t.Fatalf("userRevocationTokenPrefix %q uses only base64url bytes — a real cookie payload could carry it", userRevocationTokenPrefix)
	}

	// And prove it end to end against a genuinely encoded session.
	tok, err := Encode(&Session{Sub: "user:alice", Role: "admin", Exp: time.Now().Add(time.Hour).Unix()})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	b64 := tok[:strings.LastIndex(tok, ".")]
	if strings.HasPrefix(b64, userRevocationTokenPrefix) {
		t.Fatalf("an encoded session payload %q carries the user-revocation prefix", b64)
	}
	if _, err := base64.RawURLEncoding.DecodeString(userRevocationTokenPrefix + "alice"); err == nil {
		t.Fatalf("the sentinel token decodes as base64url — it is reachable as a payload")
	}
}

// A user entry that has passed through a node predating this change loses the
// `user` JSON field but keeps the token. Recovering the username from the
// prefix means one hop through an old node degrades nothing.
func TestChaos66_UserRevocationSurvivesAHopThroughAnOldNode(t *testing.T) {
	src := NewRevocationList()
	src.RevokeUser("dave")
	entries := src.ExportRevocations()

	// Simulate the old node: it unmarshals into a struct without the User field.
	var legacy []struct {
		Token  string `json:"token"`
		Expiry int64  `json:"expiry"`
	}
	raw, err := json.Marshal(entries)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := json.Unmarshal(raw, &legacy); err != nil {
		t.Fatalf("an old binary could not parse the new document: %v", err)
	}
	relayed := make([]RevocationEntry, 0, len(legacy))
	for _, e := range legacy {
		relayed = append(relayed, RevocationEntry{Token: e.Token, Expiry: e.Expiry})
	}

	dst := NewRevocationList()
	dst.MergeRevocations(relayed)
	if !dst.IsUserRevoked("dave") {
		t.Error("user revocation was erased by a hop through a node predating CHAOS-66")
	}
}

// DOWNGRADE. The document must stay a JSON array so a binary predating this
// change still parses the TOKEN revocations it does understand. Promoting the
// file to an object would trade a gap for a regression.
func TestChaos66_PersistedDocumentStaysDowngradeParseable(t *testing.T) {
	chaosRevocationsPath(t)
	r := NewRevocationList()
	r.Revoke("tok-c", time.Now().Add(time.Hour))
	r.RevokeUser("erin")
	if err := r.SaveRevocations(); err != nil {
		t.Fatalf("save: %v", err)
	}
	data, err := os.ReadFile(RevocationsPath())
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var legacy []struct {
		Token  string `json:"token"`
		Expiry int64  `json:"expiry"`
	}
	if err := json.Unmarshal(data, &legacy); err != nil {
		t.Fatalf("a binary predating CHAOS-66 cannot parse the document: %v", err)
	}
	var sawToken bool
	for _, e := range legacy {
		if e.Token == "tok-c" {
			sawToken = true
		}
	}
	if !sawToken {
		t.Error("the token revocation an old binary understands is not in the document")
	}
}

// DEFECT (corruption). A file that was read and could not be parsed must be
// reported as corrupt, so the caller quarantines it instead of silently
// booting with an EMPTY list — the fail-OPEN direction for this file.
func TestChaos66_CorruptFileIsReportedAsCorrupt(t *testing.T) {
	path := chaosRevocationsPath(t)
	if err := os.WriteFile(path, []byte("{ this is not a revocation list"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	err := NewRevocationList().LoadRevocations()
	if err == nil {
		t.Fatal("a corrupt revocations file loaded without error")
	}
	if !errors.Is(err, ErrRevocationsCorrupt) {
		t.Errorf("err = %v, want it to wrap ErrRevocationsCorrupt so the caller quarantines rather than overwrites", err)
	}
}

// CONTROL. A file we could NOT READ must not be classified as corrupt: the
// content may be intact behind a transient permission or I/O fault, and
// quarantining would move a healthy security-critical file aside.
func TestChaos66_UnreadableFileIsNotReportedAsCorrupt(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: mode bits do not deny reads")
	}
	path := chaosRevocationsPath(t)
	if err := os.WriteFile(path, []byte("[]"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o600) })

	err := NewRevocationList().LoadRevocations()
	if err == nil {
		t.Fatal("an unreadable revocations file loaded without error")
	}
	if errors.Is(err, ErrRevocationsCorrupt) {
		t.Error("a READ failure was classified as corruption — quarantining would move a possibly-healthy file aside")
	}
}

// DEFECT (durability reporting). A revocation that could not be written down
// must reach the observer, because the admin action reports success either way.
func TestChaos66_PersistFailureIsObserved(t *testing.T) {
	// A directory where the file should be: AtomicWrite cannot replace it.
	dir := t.TempDir()
	path := filepath.Join(dir, "revocations.json")
	if err := os.Mkdir(path, 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	withRevocationsPath(t, path)

	var seen int
	SetPersistFailureObserver(func(error) { seen++ })
	t.Cleanup(func() { SetPersistFailureObserver(nil) })

	r := NewRevocationList()
	r.RevokeUser("frank")
	if err := r.SaveRevocations(); err == nil {
		t.Fatal("save succeeded against an unwritable path")
	}
	if seen != 1 {
		t.Errorf("observer fired %d times, want 1 — a non-durable revocation must be countable", seen)
	}
}

// CONTROL. A panicking observer must never take down the admin plane it is
// reporting on (the internal/audit observer rule).
func TestChaos66_PanickingObserverIsContained(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "revocations.json")
	if err := os.Mkdir(path, 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	withRevocationsPath(t, path)

	SetPersistFailureObserver(func(error) { panic("observer blew up") })
	t.Cleanup(func() { SetPersistFailureObserver(nil) })

	r := NewRevocationList()
	r.Revoke("tok-d", time.Now().Add(time.Hour))
	if err := r.SaveRevocations(); err == nil {
		t.Fatal("save succeeded against an unwritable path")
	}
	// Reaching here without a panic is the assertion.
}

// CONTROL. No observer installed must not be a failure path, and a persisted
// save on a healthy volume must not charge the counter.
func TestChaos66_HealthySaveDoesNotChargeTheObserver(t *testing.T) {
	chaosRevocationsPath(t)
	var seen int
	SetPersistFailureObserver(func(error) { seen++ })
	t.Cleanup(func() { SetPersistFailureObserver(nil) })

	r := NewRevocationList()
	r.Revoke("tok-e", time.Now().Add(time.Hour))
	r.RevokeUser("grace")
	if err := r.SaveRevocations(); err != nil {
		t.Fatalf("save: %v", err)
	}
	if seen != 0 {
		t.Errorf("observer fired %d times on a healthy save", seen)
	}
}

// An expired user revocation must not be exported or re-merged: without this a
// revocation that has served its purpose rides the gossip forever.
func TestChaos66_ExpiredUserRevocationsArePruned(t *testing.T) {
	r := NewRevocationList()
	r.mu.Lock()
	r.users["stale"] = time.Now().Add(-time.Hour)
	r.mu.Unlock()

	for _, e := range r.ExportRevocations() {
		if e.User == "stale" {
			t.Fatal("an expired user revocation was exported")
		}
	}
	if r.UserCount() != 0 {
		t.Errorf("UserCount = %d after export, want 0 (expired entry not pruned)", r.UserCount())
	}

	dst := NewRevocationList()
	dst.MergeRevocations([]RevocationEntry{{
		Token: userRevocationTokenPrefix + "stale", User: "stale",
		Expiry: time.Now().Add(-time.Hour).Unix(),
	}})
	if dst.IsUserRevoked("stale") {
		t.Error("an expired user revocation was merged")
	}
}

// A re-delete of the same account must EXTEND the window, never shorten it on
// a gossip round trip.
func TestChaos66_MergeKeepsTheLaterUserExpiry(t *testing.T) {
	r := NewRevocationList()
	late := time.Now().Add(6 * time.Hour)
	r.MergeRevocations([]RevocationEntry{
		{Token: userRevocationTokenPrefix + "heidi", User: "heidi", Expiry: late.Unix()},
		{Token: userRevocationTokenPrefix + "heidi", User: "heidi", Expiry: time.Now().Add(time.Minute).Unix()},
	})
	r.mu.Lock()
	got := r.users["heidi"]
	r.mu.Unlock()
	if got.Unix() != late.Unix() {
		t.Errorf("expiry = %v, want the later %v — a round trip must not shorten a revocation", got, late)
	}
}

// CONTROL. The cheapest way to pass every gate above is to revoke everything,
// which would lock every operator out of their own gateway.
func TestChaos66_UnrevokedSessionsStillDecode(t *testing.T) {
	chaosRevocationsPath(t)
	restore := Revoked.SwapForTest()
	t.Cleanup(restore)

	Revoked.RevokeUser("alice")
	if err := Revoked.SaveRevocations(); err != nil {
		t.Fatalf("save: %v", err)
	}
	if err := Revoked.LoadRevocations(); err != nil {
		t.Fatalf("load: %v", err)
	}

	tok, err := Encode(&Session{Sub: "bob", Role: "admin", Exp: time.Now().Add(time.Hour).Unix()})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if _, err := Decode(tok); err != nil {
		t.Fatalf("an unrelated session was rejected: %v", err)
	}

	revoked, err := Encode(&Session{Sub: "alice", Role: "admin", Exp: time.Now().Add(time.Hour).Unix()})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if _, err := Decode(revoked); err == nil {
		t.Fatal("the revoked account's session decoded after a restart")
	}
}

// DEFECT (Codex P2). A health surface keyed on a CUMULATIVE failure counter can
// never recover: it keeps reporting a security-control failure after the
// operator has fixed the volume, until the process restarts. The counter is the
// right instrument for magnitude and the wrong one for state, so a successful
// save must be observable as recovery.
//
// This is the same bug ca_health.go records having already fixed once, which is
// why the seam exists rather than the call site being trusted to notice.
func TestChaos66_SuccessfulSaveIsObservedAsRecovery(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "blocked")
	if err := os.Mkdir(bad, 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	var failures, recoveries int
	SetPersistFailureObserver(func(error) { failures++ })
	SetPersistSuccessObserver(func() { recoveries++ })
	t.Cleanup(func() {
		SetPersistFailureObserver(nil)
		SetPersistSuccessObserver(nil)
	})

	r := NewRevocationList()
	r.RevokeUser("ivan")

	withRevocationsPath(t, bad) // a directory: AtomicWrite cannot replace it
	if err := r.SaveRevocations(); err == nil {
		t.Fatal("save succeeded against an unwritable path")
	}
	if failures != 1 || recoveries != 0 {
		t.Fatalf("after the fault: failures=%d recoveries=%d, want 1/0", failures, recoveries)
	}

	// The operator repairs the volume.
	withRevocationsPath(t, filepath.Join(dir, "revocations.json"))
	if err := r.SaveRevocations(); err != nil {
		t.Fatalf("save after repair: %v", err)
	}
	if recoveries != 1 {
		t.Errorf("recoveries = %d, want 1 — a repaired volume must be observable, or the health row latches until restart", recoveries)
	}

	// And the recovery is real: the complete live list is on disk.
	reloaded := NewRevocationList()
	withRevocationsPath(t, filepath.Join(dir, "revocations.json"))
	if err := reloaded.LoadRevocations(); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if !reloaded.IsUserRevoked("ivan") {
		t.Error("the revocation applied during the outage is not durable after recovery")
	}
}

// CONTROL. Persistence is opt-in; an unconfigured path writes nothing, so it
// must NOT be reported as a recovery — that would clear a real degradation.
func TestChaos66_UnconfiguredSaveIsNotARecovery(t *testing.T) {
	withRevocationsPath(t, "")

	var recoveries int
	SetPersistSuccessObserver(func() { recoveries++ })
	t.Cleanup(func() { SetPersistSuccessObserver(nil) })

	r := NewRevocationList()
	r.Revoke("tok-f", time.Now().Add(time.Hour))
	if err := r.SaveRevocations(); err != nil {
		t.Fatalf("save: %v", err)
	}
	if recoveries != 0 {
		t.Errorf("recoveries = %d, want 0 — nothing was written, so nothing recovered", recoveries)
	}
}

// CONTROL. A panicking success observer must be contained too, on the same
// reasoning as the failure one.
func TestChaos66_PanickingSuccessObserverIsContained(t *testing.T) {
	withRevocationsPath(t, filepath.Join(t.TempDir(), "revocations.json"))
	SetPersistSuccessObserver(func() { panic("observer blew up") })
	t.Cleanup(func() { SetPersistSuccessObserver(nil) })

	r := NewRevocationList()
	r.Revoke("tok-g", time.Now().Add(time.Hour))
	if err := r.SaveRevocations(); err != nil {
		t.Fatalf("save: %v", err)
	}
	// Reaching here without a panic is the assertion.
}
