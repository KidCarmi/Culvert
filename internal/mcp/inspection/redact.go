package inspection

import (
	"encoding/hex"

	"github.com/KidCarmi/Culvert/internal/mcp/canonical"
	"github.com/KidCarmi/Culvert/internal/mcp/inspection/dlp"
	"github.com/KidCarmi/Culvert/internal/mcp/inspection/schema"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

// ApplyRedaction resolves the ALLOW_WITH_REDACTION obligation profile and produces
// a DEEP transformed copy of args with the profile's classifications removed. It
// NEVER mutates the original request. After transforming it (1) re-runs semantic
// schema validation, (2) re-runs the DLP scan and rejects any residual
// block-disposition secret, (3) verifies the destination scope did not broaden,
// and (4) produces original/transformed canonical hashes. Any failure returns a
// typed error and NO partial transform (nil node). It fails closed when the
// profile is missing, stale, mandatory-but-unproduced, or leaves a secret behind.
//
// expectedMinRevision (0 ⇒ skip) rejects a stale profile whose revision is older
// than the caller's expectation.
func ApplyRedaction(p Profile, ref string, expectedMinRevision uint64, args *canonical.Node, compiled *schema.Compiled) (*canonical.Node, RedactionEvidence, error) {
	rp, ok := p.RedactionProfile(ref)
	if !ok || ref == "" {
		return nil, RedactionEvidence{}, redErr("missing redaction profile")
	}
	if expectedMinRevision != 0 && rp.Revision < expectedMinRevision {
		return nil, RedactionEvidence{}, redErr("stale redaction profile")
	}
	want := redactionClassSet(rp)
	orig := args
	transformed := args.Clone() // deep copy — never mutate the original
	var removed []dlp.Classification
	count := 0
	redactTree(transformed, want, &removed, &count, p.lim.MaxRedactions())

	// (1) re-validate against the tool schema.
	if compiled != nil {
		if r := compiled.Validate(transformed); !r.Valid() {
			return nil, RedactionEvidence{}, redErr("transformed value no longer satisfies the schema")
		}
	}
	// (2) re-scan DLP; any residual block-disposition secret fails closed.
	rep, err := dlp.Scan(transformed, dlp.RequestMode(), p.lim)
	if err != nil {
		return nil, RedactionEvidence{}, redErr("re-scan failed")
	}
	for i := range rep.Findings {
		if p.disposition(rep.Findings[i].Class).Blocks() {
			return nil, RedactionEvidence{}, redErr("secret remains after redaction")
		}
	}
	// (3) destination scope must not broaden.
	if broadenedDestinations(p, orig, transformed) {
		return nil, RedactionEvidence{}, redErr("destination scope broadened")
	}
	// (4) hashes.
	oh := canonical.HashNode(orig)
	th := canonical.HashNode(transformed)
	ev := RedactionEvidence{
		ProfileRef: rp.Ref, ProfileRevision: rp.Revision, Classes: dedupeClasses(removed),
		Count: count, OriginalHash: hex.EncodeToString(oh[:]), TransformedHash: hex.EncodeToString(th[:]),
		TransformedSize: len(canonical.Encode(transformed)),
	}
	return transformed, ev, nil
}

func redErr(detail string) error {
	return mcperr.New(mcperr.ReasonRedactionFailed, "inspection.redact", detail)
}

func redactionClassSet(rp RedactionProfile) map[dlp.Classification]struct{} {
	out := make(map[dlp.Classification]struct{}, len(rp.classes))
	for c := range rp.classes {
		out[c] = struct{}{}
	}
	return out
}

// redactTree redacts every string leaf of a (cloned) node in place, accumulating
// removed classifications and the redaction count under the redaction cap.
func redactTree(n *canonical.Node, want map[dlp.Classification]struct{}, removed *[]dlp.Classification, count *int, maxRedactions int) {
	if n == nil || *count >= maxRedactions {
		return
	}
	switch n.Kind {
	case canonical.KindObject:
		for i := range n.Vals {
			redactTree(n.Vals[i], want, removed, count, maxRedactions)
		}
	case canonical.KindArray:
		for i := range n.Arr {
			redactTree(n.Arr[i], want, removed, count, maxRedactions)
		}
	case canonical.KindString:
		out, rem, k := dlp.RedactLeaf(n.Str, want)
		if k > 0 {
			n.Str = out
			*count += k
			*removed = append(*removed, rem...)
		}
	}
}

// broadenedDestinations reports whether the transformed value has MORE destination
// candidates than the original (redaction may only remove, never add/broaden).
func broadenedDestinations(p Profile, orig, transformed *canonical.Node) bool {
	oc, err1 := p.extraction.Extract(orig, p.lim)
	tc, err2 := p.extraction.Extract(transformed, p.lim)
	if err1 != nil || err2 != nil {
		return true // fail closed
	}
	return len(tc) > len(oc)
}

func dedupeClasses(in []dlp.Classification) []dlp.Classification {
	seen := map[dlp.Classification]struct{}{}
	var out []dlp.Classification
	for _, c := range in {
		if _, ok := seen[c]; ok {
			continue
		}
		seen[c] = struct{}{}
		out = append(out, c)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j-1] > out[j]; j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out
}
