package catalog

import "sort"

// DriftClass is the single primary class assigned to a tool observation. Values
// are listed in the accepted-design order (TOOL-DISCOVERY-AND-DRIFT §2); the
// CLASSIFICATION PRECEDENCE is a separate, explicit ordering encoded in Classify.
type DriftClass uint8

const (
	// NoMaterialChange — the canonical fingerprint is unchanged.
	NoMaterialChange DriftClass = iota
	// SafeNarrowing — every change is MECHANICALLY PROVEN restrictive.
	SafeNarrowing
	// PrivilegeExpansion — a proven, or conservatively-classified ambiguous
	// security-relevant, broadening. Quarantine-required; never auto-allowed.
	PrivilegeExpansion
	// SemanticDrift — a behavioral/description change that is neither proven safe
	// narrowing nor proven expansion. Review-required.
	SemanticDrift
	// IdentityChange — the observed identity differs from the recorded one. A
	// server-level control; every tool behind the server is affected.
	IdentityChange
	// UnknownTool — no prior record for this (server,tool). Quarantine-required.
	UnknownTool
)

// String returns the stable drift-class code.
func (d DriftClass) String() string {
	switch d {
	case NoMaterialChange:
		return "no_material_change"
	case SafeNarrowing:
		return "safe_narrowing"
	case PrivilegeExpansion:
		return "privilege_expansion"
	case SemanticDrift:
		return "semantic_drift"
	case IdentityChange:
		return "identity_change"
	case UnknownTool:
		return "unknown_tool"
	default:
		return "invalid"
	}
}

// FieldDiff is one field-level difference. Detail is a FIXED, developer-authored
// phrase — never raw hostile schema/description content.
type FieldDiff struct {
	Field  string // input_schema | output_schema | description | destination | credential_profile | identity
	Change string // expansion | narrowing | semantic | changed
	Detail string
}

// Classify assigns exactly one DriftClass to observed relative to prior, and
// returns the field-level differences in deterministic order. The precedence is
// explicit and total, so simultaneous changes never resolve by field-visit order:
//
//  1. prior == nil                         → UnknownTool
//  2. identity differs                     → IdentityChange
//  3. any proven privilege broadening      → PrivilegeExpansion
//  4. any inconsistent behavioral change   → SemanticDrift
//  5. only provably restrictive changes    → SafeNarrowing
//  6. fingerprints equal                   → NoMaterialChange
//
// It is a pure function; a nil observed is treated as an empty (all-changed) diff.
func Classify(prior, observed *ToolRecord) (DriftClass, []FieldDiff) {
	if observed == nil {
		return NoMaterialChange, nil
	}
	if prior == nil {
		return UnknownTool, nil
	}
	if prior.Fingerprint.Identity != observed.Fingerprint.Identity {
		return IdentityChange, []FieldDiff{{Field: "identity", Change: "changed", Detail: "verified identity differs from the recorded identity"}}
	}
	if prior.Fingerprint.Equal(observed.Fingerprint) {
		return NoMaterialChange, nil
	}
	diffs := collectDiffs(prior, observed)
	sortDiffs(diffs)
	switch {
	case anyChange(diffs, "expansion"):
		return PrivilegeExpansion, diffs
	case anyChange(diffs, "semantic"):
		return SemanticDrift, diffs
	case anyChange(diffs, "narrowing"):
		return SafeNarrowing, diffs
	default:
		// Fingerprints differ but no signal was attributable: fail conservative to
		// semantic (never silently no-change or safe-narrowing).
		return SemanticDrift, append(diffs, FieldDiff{Field: "input_schema", Change: "semantic", Detail: "unattributed fingerprint change"})
	}
}

// collectDiffs gathers every field-level signal between prior and observed.
func collectDiffs(prior, observed *ToolRecord) []FieldDiff {
	var diffs []FieldDiff
	// Input schema: the privilege-relevant surface.
	if prior.Fingerprint.InputSchemaHash != observed.Fingerprint.InputSchemaHash {
		sig := diffSchema(prior.InputSchema, observed.InputSchema)
		diffs = append(diffs, sig.toFieldDiffs("input_schema")...)
		if len(sig.expansion) == 0 && len(sig.narrowing) == 0 && len(sig.ambiguous) == 0 {
			diffs = append(diffs, FieldDiff{Field: "input_schema", Change: "semantic", Detail: "input schema changed"})
		}
	}
	// Output schema: presence and content changes are behavioral (never privilege).
	diffs = append(diffs, outputSchemaDiffs(prior, observed)...)
	// Descriptive metadata (description/annotations/title): semantic.
	if prior.Fingerprint.DescriptiveHash != observed.Fingerprint.DescriptiveHash {
		diffs = append(diffs, FieldDiff{Field: "description", Change: "semantic", Detail: "description/annotations/title changed"})
	}
	// Destination class: broadened → expansion, narrowed → narrowing, else semantic.
	if d, ok := destinationDiff(prior.Fingerprint.Destination, observed.Fingerprint.Destination); ok {
		diffs = append(diffs, d)
	}
	// Credential profile: opaque, so a change cannot be PROVEN safe → conservatively
	// security-relevant broadening (expansion).
	if prior.Fingerprint.CredentialProfile != observed.Fingerprint.CredentialProfile {
		diffs = append(diffs, FieldDiff{Field: "credential_profile", Change: "expansion", Detail: "credential profile changed (unprovable as narrowing)"})
	}
	return diffs
}

// outputSchemaDiffs classifies output-schema presence/content changes as semantic
// (they change the declared response contract, not caller privilege).
func outputSchemaDiffs(prior, observed *ToolRecord) []FieldDiff {
	switch {
	case prior.Fingerprint.HasOutputSchema != observed.Fingerprint.HasOutputSchema:
		return []FieldDiff{{Field: "output_schema", Change: "semantic", Detail: "output schema presence changed"}}
	case prior.Fingerprint.HasOutputSchema && prior.Fingerprint.OutputSchemaHash != observed.Fingerprint.OutputSchemaHash:
		return []FieldDiff{{Field: "output_schema", Change: "semantic", Detail: "output schema changed"}}
	default:
		return nil
	}
}

// destinationDiff compares two destination classes. An ordered broadening is
// expansion, an ordered narrowing is narrowing, and any change touching the
// unordered DestUnknown is a semantic (ambiguous) change.
func destinationDiff(prior, observed DestinationClass) (FieldDiff, bool) {
	if prior == observed {
		return FieldDiff{}, false
	}
	pr, pok := prior.rank()
	or, ook := observed.rank()
	switch {
	case !pok || !ook:
		return FieldDiff{Field: "destination", Change: "semantic", Detail: "destination class changed (ambiguous direction)"}, true
	case or > pr:
		return FieldDiff{Field: "destination", Change: "expansion", Detail: "destination scope broadened"}, true
	default:
		return FieldDiff{Field: "destination", Change: "narrowing", Detail: "destination scope narrowed"}, true
	}
}

func anyChange(diffs []FieldDiff, change string) bool {
	for _, d := range diffs {
		if d.Change == change {
			return true
		}
	}
	return false
}

// sortDiffs orders diffs deterministically by (Field, Change, Detail).
func sortDiffs(diffs []FieldDiff) {
	sort.Slice(diffs, func(i, j int) bool {
		if diffs[i].Field != diffs[j].Field {
			return diffs[i].Field < diffs[j].Field
		}
		if diffs[i].Change != diffs[j].Change {
			return diffs[i].Change < diffs[j].Change
		}
		return diffs[i].Detail < diffs[j].Detail
	})
}
