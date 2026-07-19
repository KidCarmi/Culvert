package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// qualification_manifest_test.go — the EXECUTABLE release-evidence wall for the
// adaptive-decryption production qualification (roadmap/PR5-adaptive-decryption-
// production-qualification.md §3, §9.1).
//
// The dossier names the load-bearing guard tests that prove each qualified security
// invariant (PR1 permissive-retirement, PR2 security-generation fencing, the fail-closed
// classifier, scoped isolation, PR3 destination privacy). If one of those guard tests is
// renamed or deleted, the dossier's evidence claim silently becomes false. This test
// pins the mapping: it scans the qualified source surface for the actual `func Test…`
// definitions (the same source-scan technique as the C1 route-parity and
// config_surfaces walls) and fails if any manifest entry no longer exists.
//
// It exercises NO runtime behavior — it is pure evidence protection. Updating a qualified
// guard test's name is fine; it just has to be a conscious edit here too (which is the
// point). This is NOT a substitute for running the guard tests — CI runs those; this only
// guarantees they still exist under the names the dossier cites.

// qualManifest maps each qualified invariant group to the load-bearing guard tests the
// PR5 dossier cites as its evidence. Keep in lockstep with §3 of the dossier.
var qualManifest = map[string][]string{
	// A. PR1 — certVerification=permissive is retired (reject interactively, fail-closed
	// migrate on bulk paths, GUI⇔runtime parity).
	"A_PR1_permissive_retired": {
		"TestValidCertVerificationSet",
		"TestValidate_RejectsPermissive",
		"TestReplaceAll_MigratesPermissive",
		"TestApiDecryptionProfiles_RejectsPermissive_POST",
		"TestSnapshotApply_MigratesPermissive",
		"TestCertVerificationParity_GUIandRuntime",
	},
	// B. PR2 — security-generation fencing (gen over only security-effective fields;
	// rename preserves, security edit invalidates; narrows (scope,host)→(scope,gen,host);
	// zero-alloc hot path).
	"B_PR2_security_generation_fencing": {
		"TestSecurityGen_SecurityFieldsChangeIt",
		"TestSecurityGen_RenameStable",
		"TestSecurityGen_EveryWritePathPrecomputes",
		"TestSecurityGen_Deterministic",
		"TestContains_GenMismatchMisses",
		"TestSecGen_SecurityEditInvalidates",
		"TestSecGen_RenamePreservesExclusion",
		"TestSecGen_FailOpenToFailCloseImmediate",
		"TestBenchGate_AutoExcludeResolveAllocs",
	},
	// C. Classifier fail-closed posture (only narrow signals learn; only client-cert
	// live-rescues, and that rescue is fully observable; spoofable class identity-gated).
	"C_classifier_fail_closed": {
		"TestClassifyOriginInspectFailure_TightenedTriggers",
		"TestClassifyClientInspectFailure",
		"TestMaybeFailOpenOrigin_RescueOnlyClientCert",
		"TestRecordAutoExcludeRescue_EmitsObservability",
		"TestClientCertRescue_DecisionRealHandshakes",
		"TestClientCertRescue_SSRFRedialRejected",
		"TestConfirmCount_DistinctTokens",
		"TestClientEvidence_ADR0008_IdentityGatesClientPinned",
		"TestADR0008_ClientPinnedRequiresAuthenticatedIdentity",
		"TestExpiry_ReasonTTL",
		"TestAllReasons_Exhaustive",
	},
	// D. Scoped isolation & bounded volatile posture (one profile can't bypass for
	// another; fail-close never consults; off every config surface; bounded/deterministic).
	"D_scoped_isolation": {
		"TestScopeIsolation",
		"TestResolveSSLAction_FailCloseNeverConsults",
		"TestResolveSSLAction_CrossScopeContamination",
		"TestResolveSSLAction_EmptyCacheByteIdentical",
		"TestAutoExcludeTunables_OffExportAndRollback",
		"TestPendingBounded",
		"TestCache_ConcurrentObserveContainsRemoveListEvict",
		"TestReconfigure_DeterministicEviction",
		"TestValidateAutoExcludeTunables",
	},
	// E. PR3 — destination privacy (OFF byte-identical + zero-alloc; keyed HMAC;
	// fail-closed sentinel; URI can't leak the host in any form; key off every replication
	// surface; rotation never silently disables the posture).
	"E_PR3_destination_privacy": {
		"TestTrafficRedaction_OffIsByteIdentical",
		"TestTrafficRedaction_OffZeroAlloc",
		"TestTrafficRedaction_FailClosed",
		"TestTrafficRedaction_URICannotLeakHost",
		"TestTrafficRedaction_URIDoesNotOverRedact",
		"TestTrafficRedaction_URIScrubsPortlessHost",
		"TestTrafficRedaction_ChokepointRedactsAllFields",
		"TestTrafficRedaction_TopHostsRedacted",
		"TestTrafficRedaction_KeyNeverInExportSurface",
		"TestApiDecryptionRedaction_RotatePreservesPosture",
		"TestDecRedaction_APISurfacesScope",
	},
}

// qualSourceDirs are the directories the qualified guard tests live in, relative to the
// package source dir (which is the module root — internal/… are subdirs of it).
var qualSourceDirs = []string{
	".",
	filepath.Join("internal", "decryptprofile"),
	filepath.Join("internal", "autoexclude"),
	filepath.Join("internal", "decryptobs"),
}

// collectTestFuncNames scans every *_test.go file under the qualified source dirs and
// returns the set of top-level `func Test…` names. CWD-independent: anchored to
// pkgSourceDir() (runtime.Caller), never a bare relative read — see static_read_wall_test.go.
func collectTestFuncNames(t *testing.T) map[string]struct{} {
	t.Helper()
	funcRe := regexp.MustCompile(`(?m)^func (Test\w+)\(`)
	root := pkgSourceDir()
	found := map[string]struct{}{}
	for _, rel := range qualSourceDirs {
		dir := filepath.Join(root, rel)
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("read qualified source dir %s: %v", rel, err)
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), "_test.go") {
				continue
			}
			b, err := os.ReadFile(filepath.Join(dir, e.Name()))
			if err != nil {
				t.Fatalf("read %s/%s: %v", rel, e.Name(), err)
			}
			for _, m := range funcRe.FindAllStringSubmatch(string(b), -1) {
				found[m[1]] = struct{}{}
			}
		}
	}
	return found
}

// TestQualificationManifest asserts every guard test the PR5 dossier cites still exists in
// the source. A rename/delete without updating both the dossier and this manifest goes red.
func TestQualificationManifest(t *testing.T) {
	found := collectTestFuncNames(t)
	for group, names := range qualManifest {
		if len(names) == 0 {
			t.Errorf("qualification group %q has no guard tests — an empty evidence group is a drift bug", group)
			continue
		}
		for _, name := range names {
			if _, ok := found[name]; !ok {
				t.Errorf("qualification group %q cites guard test %q, which no longer exists in the qualified source surface — update roadmap/PR5-adaptive-decryption-production-qualification.md AND this manifest together", group, name)
			}
		}
	}
}
