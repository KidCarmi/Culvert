package main

// bulk_ref_validation.go — candidate-level reference-graph validation for the
// BULK config paths (final 2D-B correction §§14–19).
//
// objectReferenceMutationGate handles CONCURRENCY (a delete cannot interleave
// with a reference write); it says nothing about candidate CORRECTNESS. The
// bulk installers — config import, config-version rollback, and the CP→DP
// ConfigSnapshot apply — install whole object graphs at once, and their
// leaf-first apply order only guarantees that references resolve against
// whatever the candidate happens to carry; a candidate whose rule references
// a category group or decryption profile the SAME candidate does not define
// (and the node cannot otherwise resolve) used to land silently, leaving a
// DENY/DROP rule that never matches — fail-open with a 2xx.
//
// validateBulkCandidateRefs is a PURE function over one EFFECTIVE candidate
// (the state the store will hold AFTER the bulk apply), assembled by the
// per-path constructors below according to that path's own merge/replace/
// nil-skip semantics. The graph edges judged (§15):
//
//   - PolicyRule → CategoryGroup      (name, or the rename-safe ID — runtime
//     resolution is ID-first with name fallback, so the reference dangles
//     only when NEITHER resolves in the candidate)
//   - PolicyRule → DecryptionProfile  (same ID-or-name rule)
//   - CategoryGroup → URL category    (member names via the category closure)
//   - PolicyRule → URL category       (direct DestCategory, where the edge is
//     deterministic — the same closure)
//
//   - PolicyRule → FileProfile        (2D-C §16 — the 2D-B legacy exclusion is
//     CLOSED: the reference model is deterministic now. A non-empty
//     authoritative FileProfileID must resolve in the candidate — never by
//     name (anti-rebinding); an ID-less legacy reference resolves by
//     candidate name or the compiled fileProfileExts map, exactly as
//     enforcement does.)
//
// CATEGORY CLOSURE: a category NAME resolves against the candidate's OWN
// category entries (any BuiltIn flag — after apply they are recompose input)
// PLUS the extra live authority layers the applying node serves at runtime:
// the signed effective view's classes and the UT1 community categories. A
// candidate-carried or authority-served name is never rejected (a legitimate
// feed category is not a writable catStore object); a name that resolves in
// NO layer is a dangling reference and refuses the WHOLE candidate — never a
// silently-dropped rule or a partial apply (§14).
//
// All name matching is case-insensitive, mirroring the stores
// (catgroup/decryptprofile key on ToLower; urlcat matches EqualFold).

import (
	"fmt"
	"strings"

	"github.com/KidCarmi/Culvert/internal/catoverride"
	"github.com/KidCarmi/Culvert/internal/feedsync"
	"github.com/KidCarmi/Culvert/internal/hostutil"
)

// bulkRefViolation names the first unresolvable reference in a bulk candidate.
type bulkRefViolation struct {
	Owner string // e.g. `policy rule "x"` | `category group "g"`
	Type  string // "category" | "category-group" | "decryption-profile"
	Name  string
}

func (v *bulkRefViolation) Error() string {
	return fmt.Sprintf("%s references %s %q, which the candidate does not define and no current authority resolves", v.Owner, v.Type, v.Name)
}

// bulkCandidate is one effective post-apply state plus which edges the
// calling path can judge (a path skips an edge when its candidate does not
// carry the referenced kind — the store keeps its live objects, so a
// self-contained verdict is impossible and the check must not guess).
type bulkCandidate struct {
	Rules    []PolicyRule
	Groups   []CategoryGroup
	Profiles []DecryptionProfile
	// FileProfiles is the candidate file-profile set (2D-C §16 — the legacy
	// exclusion is closed now that the reference model is deterministic:
	// ID-first, no dangling-ID name retarget, legacy map for ID-less names).
	FileProfiles []*FileExtProfile

	CheckRuleGroups       bool
	CheckRuleProfiles     bool
	CheckRuleFileProfiles bool
	CheckCategories       bool
	// CategoryOK is the category-name closure (candidate entries + live
	// view/UT1 layers). Required when CheckCategories is set.
	CategoryOK func(name string) bool
}

// postApplyCategoryClosure builds the case-insensitive category-name predicate
// over the POST-APPLY effective authority of a bulk candidate (final
// bulk-integrity correction §§4–8): the authority that will exist AFTER the
// candidate taxonomy AND the candidate override set apply, mirroring the
// runtime source model (resolveFusion / referencedCategoryResolvable) exactly:
//
//   - NO effective view armed: the full candidate taxonomy + UT1 (the
//     lifecycle is unarmed, so overrides never reach the policy path).
//   - Source == embedded: the view is recomposed FROM catStore's BuiltIn
//     taxonomy, so the candidate's BuiltIn entries form the raw base and the
//     candidate override set composes over it; authority = candidate
//     BuiltIn=false admin names ∪ composed embedded classes ∪ UT1.
//   - Source == downloaded/cached/resumed: the classes come from the SIGNED
//     generation — a candidate BuiltIn=true catStore row is NOT authority
//     merely for being present (§4/§5). The raw base is the live view's
//     retained pre-override signed classes (baseClasses — the same input the
//     production recompose uses; the bulk paths never replace the generation
//     itself), the candidate override set composes over it; authority =
//     candidate BuiltIn=false admin names ∪ composed signed classes ∪ UT1.
//
// Composition reuses the runtime's own PURE seams (catoverride.ComposeView /
// ComposeMembership) over the RAW base — never over the already-composed live
// entries, which would double-apply the current overrides (§7). The view
// pointer is read ONCE so every judgement in one run is against one authority
// state. The authority set is built lazily on first use so callers that judge
// no category edge pay nothing.
func postApplyCategoryClosure(cands []CategoryEntry, ov CategoryOverrides) func(string) bool {
	view := saasEffectiveView.Current()
	var names map[string]struct{}
	build := func() map[string]struct{} {
		out := make(map[string]struct{}, len(cands))
		if view == nil {
			for i := range cands {
				out[strings.ToLower(cands[i].Name)] = struct{}{}
			}
			return out
		}
		// Admin tier: candidate BuiltIn=false names only.
		for i := range cands {
			if !cands[i].BuiltIn {
				out[strings.ToLower(cands[i].Name)] = struct{}{}
			}
		}
		// View tier: candidate overrides composed over the RAW base.
		var baseMembers map[string][]string
		if view.Source == sourceEmbedded {
			baseMembers = candidateBuiltInMemberships(cands)
		} else {
			base := view.baseClasses()
			baseMembers = make(map[string][]string, len(base))
			for h, c := range base {
				baseMembers[h] = []string{c}
			}
		}
		for _, cats := range catoverride.ComposeMembership(baseMembers, ov) {
			for _, c := range cats {
				out[strings.ToLower(c)] = struct{}{}
			}
		}
		return out
	}
	return func(name string) bool {
		if name == "" {
			return true
		}
		if names == nil {
			names = build()
		}
		if _, ok := names[strings.ToLower(name)]; ok {
			return true
		}
		if communityDB != nil {
			for _, c := range feedsync.MappedCategories() {
				if strings.EqualFold(c, name) {
					return true
				}
			}
		}
		return false
	}
}

// candidateBuiltInMemberships derives the embedded-baseline membership map
// from a CANDIDATE taxonomy slice — the pure analogue of
// catStore.BuiltInHostMemberships over the entries the bulk apply will
// install (same normalization, same case-insensitive dedupe).
func candidateBuiltInMemberships(cands []CategoryEntry) map[string][]string {
	out := make(map[string][]string)
	for i := range cands {
		if !cands[i].BuiltIn {
			continue
		}
		for _, h := range cands[i].Hosts {
			nh := hostutil.NormalizeHost(strings.TrimSpace(h))
			if nh == "" {
				continue
			}
			dup := false
			for _, c := range out[nh] {
				if strings.EqualFold(c, cands[i].Name) {
					dup = true
					break
				}
			}
			if !dup {
				out[nh] = append(out[nh], cands[i].Name)
			}
		}
	}
	return out
}

// canonicalizeCandidateRuleRefs is the PURE candidate analogue of
// stampObjectRefIDs (final bulk-integrity correction §§1–2): an INCOMING
// import rule's NAME is the intent and its object-link IDs are untrusted, so
// the IDs are discarded and re-derived from the names against the CANDIDATE
// object sets — which may themselves be supplied by the same backup and are
// not live yet, so the live-global stamp cannot be used. An unknown name
// yields an empty ID, exactly what importPolicyRules will install; a valid
// unrelated client ID can therefore never make an invalid name pass
// validation, and a mismatched name/ID pair binds to the NAME's object.
func canonicalizeCandidateRuleRefs(r *PolicyRule, groups []CategoryGroup, profiles []DecryptionProfile, fileProfiles []*FileExtProfile) {
	r.DestCategoryGroupID = ""
	if r.DestCategoryGroup != "" {
		for i := range groups {
			if strings.EqualFold(groups[i].Name, r.DestCategoryGroup) {
				r.DestCategoryGroupID = groups[i].ID
				break
			}
		}
	}
	r.DecryptionProfileID = ""
	if r.DecryptionProfile != "" {
		for i := range profiles {
			if strings.EqualFold(profiles[i].Name, r.DecryptionProfile) {
				r.DecryptionProfileID = profiles[i].ID
				break
			}
		}
	}
	// File profile (2D-C promotion): same doctrine — the NAME is import
	// intent, the ID is derived from the candidate set; a legacy built-in
	// name resolving only through the compiled map legitimately carries no ID.
	r.FileProfileID = ""
	if r.FileProfile != "" && r.FileProfile != FileProfileNone {
		for i := range fileProfiles {
			if strings.EqualFold(fileProfiles[i].Name, string(r.FileProfile)) {
				r.FileProfileID = fileProfiles[i].ID
				break
			}
		}
	}
}

// validateBulkCandidateRefs judges every enabled edge of the candidate graph
// and returns the FIRST violation (the callers refuse the whole candidate —
// never truncate, never silently drop a rule).
func validateBulkCandidateRefs(c bulkCandidate) error {
	if c.CheckCategories {
		for i := range c.Groups {
			for _, m := range c.Groups[i].Categories {
				if strings.TrimSpace(m) == "" {
					continue
				}
				if !c.CategoryOK(m) {
					return &bulkRefViolation{Owner: fmt.Sprintf("category group %q", c.Groups[i].Name), Type: "category", Name: m}
				}
			}
		}
	}
	groupNames := make(map[string]struct{}, len(c.Groups))
	groupIDs := make(map[string]struct{}, len(c.Groups))
	for i := range c.Groups {
		groupNames[strings.ToLower(c.Groups[i].Name)] = struct{}{}
		if c.Groups[i].ID != "" {
			groupIDs[c.Groups[i].ID] = struct{}{}
		}
	}
	profNames := make(map[string]struct{}, len(c.Profiles))
	profIDs := make(map[string]struct{}, len(c.Profiles))
	for i := range c.Profiles {
		profNames[strings.ToLower(c.Profiles[i].Name)] = struct{}{}
		if c.Profiles[i].ID != "" {
			profIDs[c.Profiles[i].ID] = struct{}{}
		}
	}
	for i := range c.Rules {
		r := &c.Rules[i]
		owner := fmt.Sprintf("policy rule %q", r.Name)
		if c.CheckRuleGroups && r.DestCategoryGroup != "" {
			if _, byName := groupNames[strings.ToLower(r.DestCategoryGroup)]; !byName {
				if _, byID := groupIDs[r.DestCategoryGroupID]; !byID || r.DestCategoryGroupID == "" {
					return &bulkRefViolation{Owner: owner, Type: "category-group", Name: r.DestCategoryGroup}
				}
			}
		}
		if c.CheckRuleProfiles && r.DecryptionProfile != "" {
			if _, byName := profNames[strings.ToLower(r.DecryptionProfile)]; !byName {
				if _, byID := profIDs[r.DecryptionProfileID]; !byID || r.DecryptionProfileID == "" {
					return &bulkRefViolation{Owner: owner, Type: "decryption-profile", Name: r.DecryptionProfile}
				}
			}
		}
		if c.CheckCategories && r.DestCategory != CategoryAny && r.DestCategory != "" {
			if !c.CategoryOK(string(r.DestCategory)) {
				return &bulkRefViolation{Owner: owner, Type: "category", Name: string(r.DestCategory)}
			}
		}
		if c.CheckRuleFileProfiles && r.FileProfile != "" && r.FileProfile != FileProfileNone {
			if !fileProfileRefResolves(r, c.FileProfiles) {
				return &bulkRefViolation{Owner: owner, Type: "file-profile", Name: string(r.FileProfile)}
			}
		}
	}
	return nil
}

// fileProfileRefResolves judges one rule's file-profile reference against the
// candidate profile set, mirroring the ENFORCEMENT resolution exactly (2D-C):
// a non-empty authoritative ID must resolve in the candidate — never by name
// (the anti-rebinding doctrine); an ID-less (legacy/un-migrated) reference
// resolves by candidate name or the compiled fileProfileExts legacy map.
//
// TRUST-DOMAIN CLASSIFICATION (2D-C recovery correction §10): the legacy-map
// arm is DELIBERATELY retained here, unlike the interactive door
// (validateRuleObjectRefs), because the bulk candidates legitimately carry
// historical shapes:
//   - modern exports/snapshots carry FileProfileID (the ID arm judges them);
//   - historical pre-2D-C backups and untouched live rules in merge
//     candidates are ID-less with names that may resolve ONLY in the
//     compiled map (their enforcement uses that same fallback, so rejecting
//     them would refuse legitimate restores);
//   - rollback / CP snapshots are applied verbatim as captured.
//
// The invariant that matters is upheld at the other end: the INTERACTIVE
// modern write door can never manufacture a NEW ID-less reference, so the
// legacy shape only ever enters through evidence-bearing historical inputs.
func fileProfileRefResolves(r *PolicyRule, profiles []*FileExtProfile) bool {
	if r.FileProfileID != "" {
		for _, p := range profiles {
			if p.ID == r.FileProfileID {
				return true
			}
		}
		return false
	}
	for _, p := range profiles {
		if strings.EqualFold(p.Name, string(r.FileProfile)) {
			return true
		}
	}
	_, legacy := fileProfileExts[r.FileProfile]
	return legacy
}

// ─── Per-path effective-candidate constructors ─────────────────────────────

// effectiveImportSlice reproduces the import's per-kind apply semantics:
// absent/empty skips in BOTH modes (import never wipes), replace installs the
// incoming slice, merge upserts by name (incoming wins).
func effectiveImportSlice[T any](live, incoming []T, replaceMode bool, key func(T) string) []T {
	if len(incoming) == 0 {
		return live
	}
	if replaceMode {
		return incoming
	}
	return mergeByName(live, incoming, key)
}

// effectiveImportRules reproduces importPolicyRules' semantics: replace swaps
// the whole set (when carried); merge upserts by identity — stable rule ID
// first, then a case-insensitive name fallback, else append.
//
// TRUST BOUNDARY (§2, mirrors the interactive doctrine): every INCOMING rule
// is CANONICALIZED against the candidate object sets before it joins the
// effective candidate — its object-link IDs are discarded and re-derived from
// its NAMES (canonicalizeCandidateRuleRefs), exactly as importPolicyRules'
// stampObjectRefIDs will do at apply time (by then the candidate objects are
// installed, so the two derivations agree). The validator therefore judges
// the rule the import will ACTUALLY install, and a smuggled unrelated ID can
// never satisfy validation for an unresolvable name. UNTOUCHED live rules in
// merge/never-wipe candidates are carried verbatim and retain their existing
// ID-authoritative semantics — the import does not restamp them.
func effectiveImportRules(b *configBackup, replaceMode bool, groups []CategoryGroup, profiles []DecryptionProfile, fileProfiles []*FileExtProfile) []PolicyRule {
	canon := func(r PolicyRule) PolicyRule {
		canonicalizeCandidateRuleRefs(&r, groups, profiles, fileProfiles)
		return r
	}
	if replaceMode && len(b.PolicyRules) > 0 {
		out := make([]PolicyRule, len(b.PolicyRules))
		for i := range b.PolicyRules {
			out[i] = canon(b.PolicyRules[i])
		}
		return out
	}
	out := policyStore.List()
	for i := range b.PolicyRules {
		in := canon(b.PolicyRules[i])
		idx := -1
		if in.ID != "" {
			for j := range out {
				if out[j].ID == in.ID {
					idx = j
					break
				}
			}
		}
		if idx < 0 && in.Name != "" {
			for j := range out {
				if strings.EqualFold(out[j].Name, in.Name) {
					idx = j
					break
				}
			}
		}
		if idx >= 0 {
			out[idx] = in
		} else {
			out = append(out, in)
		}
	}
	return out
}

// effectiveImportOverrides reproduces importCategoryOverrides' semantics for
// the post-apply preview: absent/empty incoming ⇒ the live set is retained;
// replace ⇒ incoming; merge ⇒ mergeCategoryOverrides(live, incoming).
func effectiveImportOverrides(b *configBackup, replaceMode bool) CategoryOverrides {
	if b.CategoryOverrides == nil || categoryOverridesEmpty(*b.CategoryOverrides) {
		return globalCategoryOverrides.Get()
	}
	if replaceMode {
		return *b.CategoryOverrides
	}
	return mergeCategoryOverrides(globalCategoryOverrides.Get(), *b.CategoryOverrides)
}

// validateImportCandidateRefs constructs the EFFECTIVE imported candidate per
// the request's merge/replace mode and validates its whole graph BEFORE any
// store mutation — a dangling reference refuses the ENTIRE import with a 400
// (§16). Never-wipe semantics are preserved exactly: an absent section leaves
// the live objects, which then participate in the judged candidate (so a
// replace-mode taxonomy import that would strand a LIVE rule's reference is
// refused too). Caller must hold the exclusive side of
// objectReferenceMutationGate so the live halves cannot shift between this
// verdict and the apply.
func validateImportCandidateRefs(b *configBackup, replaceMode bool) error {
	cats := effectiveImportSlice(catStore.All(), b.URLCategories, replaceMode,
		func(e CategoryEntry) string { return e.Name })
	groups := effectiveImportSlice(globalCategoryGroups.List(), b.CategoryGroups, replaceMode,
		func(g CategoryGroup) string { return g.Name })
	profiles := effectiveImportSlice(globalDecryptionProfiles.List(), b.DecryptionProfiles, replaceMode,
		func(p DecryptionProfile) string { return p.Name })
	// File profiles are deliberately NOT on the export/import surface (Finding
	// 10.3 registry: ConfigSnapshot-only), so the candidate profile set is the
	// LIVE store — the only set the imported rules can resolve against. The
	// exported RULES carry fileProfileId, but import intent is the NAME
	// (canonicalized above), preserving the interactive doctrine.
	fileProfiles := globalProfileStore.List()
	return validateBulkCandidateRefs(bulkCandidate{
		Rules:                 effectiveImportRules(b, replaceMode, groups, profiles, fileProfiles),
		Groups:                groups,
		Profiles:              profiles,
		FileProfiles:          fileProfiles,
		CheckRuleGroups:       true,
		CheckRuleProfiles:     true,
		CheckRuleFileProfiles: true,
		CheckCategories:       true,
		CategoryOK:            postApplyCategoryClosure(cats, effectiveImportOverrides(b, replaceMode)),
	})
}

// validateRestoredCandidateRefs constructs the candidate a config-version
// rollback would restore — per-field nil-skip semantics: a nil section keeps
// the LIVE objects, a non-nil (including empty) section replaces wholesale —
// and validates its whole graph. A dangling reference refuses the ENTIRE
// rollback (truthful 400, nothing applied) instead of restoring a rulebase
// whose DENY/DROP rules silently stopped matching (§17).
func validateRestoredCandidateRefs(b *configBackup) error {
	cats := catStore.All()
	if b.URLCategories != nil {
		cats = b.URLCategories
	}
	groups := globalCategoryGroups.List()
	if b.CategoryGroups != nil {
		groups = b.CategoryGroups
	}
	profiles := globalDecryptionProfiles.List()
	if b.DecryptionProfiles != nil {
		profiles = b.DecryptionProfiles
	}
	rules := policyStore.List()
	if b.PolicyRules != nil {
		rules = b.PolicyRules
	}
	// Rollback candidate overrides: nil section keeps the live set; a non-nil
	// section (including empty) is a wholesale replacement — exactly
	// applyConfigBackup's semantics.
	ov := globalCategoryOverrides.Get()
	if b.CategoryOverrides != nil {
		ov = *b.CategoryOverrides
	}
	// §10 ID/name semantics: unlike the import, a restored rulebase is applied
	// VERBATIM (policyStore.ReplaceAll — no restamp), and its historical
	// object-link IDs are legitimately ID-authoritative at runtime (ID-first
	// resolution with name fallback). The validator therefore judges the
	// restored rules exactly as captured — ID-or-name — and never converts
	// them to the interactive name-intent doctrine.
	// File profiles are not on the rollback surface (ConfigSnapshot-only), so
	// the restored candidate's profile set is the LIVE store. Restored rules
	// are applied VERBATIM (ID-authoritative where stamped) and judged so.
	return validateBulkCandidateRefs(bulkCandidate{
		Rules:                 rules,
		Groups:                groups,
		Profiles:              profiles,
		FileProfiles:          globalProfileStore.List(),
		CheckRuleGroups:       true,
		CheckRuleProfiles:     true,
		CheckRuleFileProfiles: true,
		CheckCategories:       true,
		CategoryOK:            postApplyCategoryClosure(cats, ov),
	})
}

// validateSnapshotRefGraph judges the CP→DP ConfigSnapshot's object graph
// (§18): deterministic, both-sides-carried checks only. A nil slice means
// "the snapshot does not carry this kind — the DP keeps its live objects", so
// an edge is judged ONLY when the snapshot carries BOTH its sides (guessing
// against transient DP state would reject legitimate snapshots); the
// production CP always carries all four kinds, so the real path judges every
// edge. The category closure still admits the applying node's live view/UT1
// layers — a group member naming a signed-feed class is legitimate even
// though the feed classes are never part of the snapshot's URLCategories. An
// invalid graph rejects the ENTIRE snapshot: config sync keeps the last valid
// config rather than installing a rulebase whose references dangle.
func validateSnapshotRefGraph(snap ConfigSnapshot) error {
	snapFileProfiles := make([]*FileExtProfile, len(snap.FileProfiles))
	for i := range snap.FileProfiles {
		snapFileProfiles[i] = &snap.FileProfiles[i]
	}
	c := bulkCandidate{
		Rules:                 snap.PolicyRules,
		Groups:                snap.CategoryGroups,
		Profiles:              snap.DecryptionProfiles,
		FileProfiles:          snapFileProfiles,
		CheckRuleGroups:       snap.PolicyRules != nil && snap.CategoryGroups != nil,
		CheckRuleProfiles:     snap.PolicyRules != nil && snap.DecryptionProfiles != nil,
		CheckRuleFileProfiles: snap.PolicyRules != nil && snap.FileProfiles != nil,
		CheckCategories:       snap.URLCategories != nil && (snap.CategoryGroups != nil || snap.PolicyRules != nil),
	}
	if c.CheckCategories {
		// A nil Rules/Groups slice simply contributes no edges to the walk, so
		// the both-sides-carried scoping needs no further special-casing here.
		//
		// Snapshot candidate overrides (§7): non-nil ⇒ the CP's authoritative
		// replacement (exactly applySnapshotSaaSFeed's semantics), nil ⇒ the
		// applying node keeps its current set — which is then the post-apply
		// set the preview must compose. §10 ID/name semantics: snapshot rules
		// are CP-stamped and applied verbatim (ReplaceAll — no DP restamp), so
		// their IDs are legitimately authoritative and the validator judges
		// them ID-or-name as captured, never re-canonicalized.
		ov := globalCategoryOverrides.Get()
		if snap.CategoryOverrides != nil {
			ov = *snap.CategoryOverrides
		}
		c.CategoryOK = postApplyCategoryClosure(snap.URLCategories, ov)
	}
	return validateBulkCandidateRefs(c)
}
