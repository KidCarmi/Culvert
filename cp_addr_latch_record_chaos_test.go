package main

// cp_addr_latch_record_chaos_test.go — CHAOS-71: the address-rejection latch
// is part of the generation-guarded publish record (Codex P2 4299503319 on
// #1556). An address publish that found the list already current used to clear
// the latch unconditionally, under s.mu, outside the publish generation: a
// newer topology's failure that had armed it (and paged, or queued its page
// before the webhooks loaded) was erased, so its next retry paged again and
// its queued page was dropped at the flush.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// cpAddrLatchInterleavings are the two orders in which topology B's failure
// can land inside topology A's "already up to date" publish: while A builds
// (before A's up-to-date decision), and after A's decision but before A
// records its outcome.
var cpAddrLatchInterleavings = []struct {
	name string
	// publishA runs A's owned publish of upToDate with failB injected at the
	// interleaving point, and returns A's error.
	publishA func(s *ConfigStore, upToDate func() []string, failB func()) error
}{
	{"b_fails_while_a_builds", func(s *ConfigStore, upToDate func() []string, failB func()) error {
		_, err := s.publishOwnedCPAddresses("config_publish", func() []string {
			failB()
			return upToDate()
		})
		return err
	}},
	{"b_fails_between_a_decision_and_a_clear", func(s *ConfigStore, upToDate func() []string, failB func()) error {
		// publishOwnedCPAddresses, step by step, so B lands exactly between
		// the up-to-date decision (UpdateCPAddressesFrom) and the record.
		gen := s.cpAddrPublishGen()
		changed, err := s.UpdateCPAddressesFrom(upToDate)
		if changed || err != nil {
			return err
		}
		failB()
		note := s.noteCPAddrPublish("config_publish", err, gen)
		if note.page || note.startRetry {
			panic("an up-to-date outcome asked to page or retry")
		}
		return nil
	}},
}

// cpAssertBLatchSurvived checks that B's episode is still open and reported
// after A's stale "up to date" outcome was recorded.
func cpAssertBLatchSurvived(t *testing.T, s *ConfigStore, episode uint64) {
	t.Helper()
	st := s.cpAddrPublishSnapshot()
	if !st.pending || st.trigger != haTransitionPromote {
		t.Errorf("A's stale up-to-date cleared B's pending state: %+v", st)
	}
	if !st.rejectPaged || st.rejectEpisode != episode || !s.cpAddrRejectEpisodeOpen(episode) {
		t.Errorf("A's stale up-to-date cleared B's page latch (paged=%v episode=%d, want %d)", st.rejectPaged, st.rejectEpisode, episode)
	}
	if msg, _ := s.LastPublishError(); msg == "" {
		t.Error("A's stale up-to-date cleared B's rejection from LastPublishError")
	}
}

// TestChaos71_StaleUpToDateKeepsANewerRejectionLatch_Direct — the webhooks are
// loaded: B's failure pages once; A's stale up-to-date must leave B's latch,
// so B's retries stay silent.
func TestChaos71_StaleUpToDateKeepsANewerRejectionLatch_Direct(t *testing.T) {
	for _, il := range cpAddrLatchInterleavings {
		t.Run(il.name, func(t *testing.T) {
			pages := cpRejectedPages(t)
			s, srcB, runRetries := cpOwnedRejectingStore(t)
			committed := append([]string(nil), s.Get().CPAddresses...)
			upToDate := func() []string { return committed }
			var episode uint64
			failB := func() {
				if _, err := s.publishOwnedCPAddresses(haTransitionPromote, srcB); err == nil {
					t.Fatal("precondition: topology B's oversized publish was accepted")
				}
				episode = s.cpAddrPublishSnapshot().rejectEpisode
			}

			if err := il.publishA(s, upToDate, failB); err != nil {
				t.Fatalf("A's up-to-date publish: %v", err)
			}
			if got := pages(); got != 1 {
				t.Fatalf("B's rejection paged %d time(s), want 1", got)
			}
			cpAssertBLatchSurvived(t, s, episode)

			runRetries(3) // B's source is still oversized
			if got := pages(); got != 1 {
				t.Errorf("B's retries paged again after A's stale up-to-date (%d pages in total, want 1)", got)
			}
			if st := s.cpAddrPublishSnapshot(); !st.pending || st.attempts != 4 {
				t.Errorf("pending state after B's retries = %+v, want pending with 4 attempts", st)
			}
		})
	}
}

// TestChaos71_StaleUpToDateKeepsANewerRejectionLatch_Queued — before the
// webhooks load (a persisted leader's boot): B's page is queued, valid while
// its episode is open. A's stale up-to-date must not invalidate it: the flush
// delivers it exactly once, and B's retries before and after stay silent.
func TestChaos71_StaleUpToDateKeepsANewerRejectionLatch_Queued(t *testing.T) {
	for _, il := range cpAddrLatchInterleavings {
		t.Run(il.name, func(t *testing.T) {
			direct, flushed := cpBootPages(t)
			s, srcB, runRetries := cpOwnedRejectingStore(t)
			committed := append([]string(nil), s.Get().CPAddresses...)
			upToDate := func() []string { return committed }
			var episode uint64
			failB := func() {
				if _, err := s.publishOwnedCPAddresses(haTransitionPromote, srcB); err == nil {
					t.Fatal("precondition: topology B's oversized publish was accepted")
				}
				episode = s.cpAddrPublishSnapshot().rejectEpisode
			}

			if err := il.publishA(s, upToDate, failB); err != nil {
				t.Fatalf("A's up-to-date publish: %v", err)
			}
			cpAssertBLatchSurvived(t, s, episode)
			runRetries(2) // before the webhooks load
			if d := direct(); d != 0 {
				t.Fatalf("%d page(s) fired before the webhooks loaded", d)
			}

			flushStartupAlerts()
			if f := flushed(); f != 1 {
				t.Fatalf("the startup flush delivered %d config_snapshot_rejected page(s), want B's queued page exactly once", f)
			}
			runRetries(2)
			if d, f := direct(), flushed(); d != 0 || f != 1 {
				t.Errorf("B's retries paged again after the flush (direct=%d flushed=%d)", d, f)
			}
		})
	}
}

// TestChaos71_Wall_AddressRejectionLatchHasOneWriter: the address-rejection
// latch (rejectPaged, rejectEpisode) is touched only by its single writer
// (noteCPAddrPublish), the ownership reset (resetCPAddrPublish) and the
// queued page's validity read (cpAddrRejectEpisodeOpen), all under addrPubMu
// and the publish generation. Its error text (rejectErr, rejectErrTS) is
// assigned only by the writer; LastPublishError reads it from a snapshot. No
// other code — the commit path, rejectPublish, an up-to-date branch — can
// arm or clear it.
func TestChaos71_Wall_AddressRejectionLatchHasOneWriter(t *testing.T) {
	latchOK := map[string]bool{"noteCPAddrPublish": true, "resetCPAddrPublish": true, "cpAddrRejectEpisodeOpen": true}
	dir := pkgSourceDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	seen := map[string]bool{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, perr := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if perr != nil {
			t.Fatalf("parse %s: %v", name, perr)
		}
		for _, decl := range f.Decls {
			if gd, ok := decl.(*ast.GenDecl); ok && gd.Tok == token.TYPE {
				continue // the field declarations themselves
			}
			cpCheckAddrLatchAccess(t, fset, decl, latchOK, seen)
		}
	}
	for fn := range latchOK {
		if !seen[fn] {
			t.Errorf("the wall saw no latch access in %s — its selectors have gone stale", fn)
		}
	}
}

// cpCheckAddrLatchAccess reports every latch-field use in decl outside
// latchOK, and every assignment of the rejection text outside the writer.
// seen records which owners touched the latch.
func cpCheckAddrLatchAccess(t *testing.T, fset *token.FileSet, decl ast.Decl, latchOK, seen map[string]bool) {
	t.Helper()
	owner := cpTopLevelName(decl)
	ast.Inspect(decl, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.Ident:
			if x.Name == "rejectPaged" || x.Name == "rejectEpisode" {
				seen[owner] = true
				if !latchOK[owner] {
					t.Errorf("%s: %s touches the address-rejection latch field %s — only noteCPAddrPublish (under the publish generation) may arm or clear it",
						fset.Position(x.Pos()), owner, x.Name)
				}
			}
		case *ast.AssignStmt:
			if owner == "noteCPAddrPublish" {
				return true
			}
			for _, lhs := range x.Lhs {
				if sel, ok := lhs.(*ast.SelectorExpr); ok && (sel.Sel.Name == "rejectErr" || sel.Sel.Name == "rejectErrTS") {
					t.Errorf("%s: %s assigns the address rejection text %s — only noteCPAddrPublish may", fset.Position(sel.Pos()), owner, sel.Sel.Name)
				}
			}
		}
		return true
	})
}

// TestChaos71_QueuedPageOfAReplacedOwnerIsDropped: releasing ownership ends
// the episode, so its queued page drops at the flush, and the next owner's
// first rejection is a NEW episode number — never one the old owner's queued
// page could match. Exactly one page (the live episode's) is delivered.
func TestChaos71_QueuedPageOfAReplacedOwnerIsDropped(t *testing.T) {
	_, flushed := cpBootPages(t)
	s, src, _ := cpOwnedRejectingStore(t)
	if err := s.reconcileCPAddressesFrom(haTransitionResume, src); err == nil {
		t.Fatal("precondition: the boot republish was accepted")
	}
	s.releaseCPAddressSource()
	s.setCPAddressSource(src)
	if err := s.reconcileCPAddressesFrom(haTransitionEnable, src); err == nil {
		t.Fatal("precondition: the new owner's republish was accepted")
	}
	flushStartupAlerts()
	if f := flushed(); f != 1 {
		t.Errorf("the startup flush delivered %d config_snapshot_rejected page(s), want 1 — the released owner's page must drop", f)
	}
}
