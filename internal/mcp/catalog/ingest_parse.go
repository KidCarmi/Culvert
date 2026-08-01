package catalog

import (
	"crypto/sha256"
	"encoding/binary"

	"github.com/KidCarmi/Culvert/internal/mcp/canonical"
	"github.com/KidCarmi/Culvert/internal/mcp/limits"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/registry"
)

// DiscoveryInput is the explicit, already-received input to Ingest. Raw is one
// decoded-on-the-wire-elsewhere tools/list result's exact bytes; Identity is the
// freshly VERIFIED upstream identity for this discovery cycle (compared against
// the registry pin); Destinations carries the empirically observed per-tool
// destination class (a tool absent from the map is DestUnknown). PR-2 fetches
// none of this over the network.
type DiscoveryInput struct {
	ServerID     registry.ServerID
	Identity     registry.Identity
	Raw          []byte
	Destinations map[string]DestinationClass
}

// resultMembers is the exact known top-level member allowlist of a tools/list
// result. Unknown members are rejected (no silent envelope expansion).
var resultMembers = map[string]struct{}{"tools": {}, "nextCursor": {}}

// toolMembers is the exact known member allowlist of one tool object.
var toolMembers = map[string]struct{}{
	"name": {}, "inputSchema": {}, "outputSchema": {}, "description": {}, "annotations": {}, "title": {},
}

// parseDiscovery decodes and strictly validates a discovery result against the
// supported V1 contract, returning the freshly-built (eligibility-unset) tool
// records in tools-array order. It performs exactly one hostile-input decode
// (canonical.Decode) and schema-canonicalizes each schema from the resulting
// trusted tree. server supplies the per-tool credential profile and identity pin.
func parseDiscovery(server registry.ServerRecord, in DiscoveryInput, lim limits.CatalogLimits) ([]*ToolRecord, error) {
	if len(in.Raw) > lim.MaxDiscoveryBytes() {
		return nil, mcperr.New(mcperr.ReasonResourceLimit, "catalog.ingest", "discovery result bytes")
	}
	root, err := canonical.Decode(in.Raw, discoveryBounds(lim))
	if err != nil {
		return nil, err // malformed_json / resource_limit / canonicalization_failed
	}
	if root.Kind != canonical.KindObject {
		return nil, malformedDiscovery("discovery result is not a JSON object")
	}
	for _, k := range root.Keys {
		if _, ok := resultMembers[k]; !ok {
			return nil, malformedDiscovery("unknown discovery result member")
		}
	}
	toolsNode, ok := root.Get("tools")
	if !ok {
		return nil, malformedDiscovery("discovery result missing tools array")
	}
	if toolsNode.Kind != canonical.KindArray {
		return nil, malformedDiscovery("tools is not an array")
	}
	if len(toolsNode.Arr) > lim.MaxToolsPerServer() {
		return nil, mcperr.New(mcperr.ReasonCapacityExceeded, "catalog.ingest", "tools per server capacity reached")
	}
	records := make([]*ToolRecord, 0, len(toolsNode.Arr))
	seen := make(map[string]struct{}, len(toolsNode.Arr))
	for _, tn := range toolsNode.Arr {
		rec, err := parseTool(server, in, tn, lim, seen)
		if err != nil {
			return nil, err
		}
		records = append(records, rec)
	}
	return records, nil
}

// parseTool validates one tool object and builds its record + fingerprint.
func parseTool(server registry.ServerRecord, in DiscoveryInput, tn *canonical.Node, lim limits.CatalogLimits, seen map[string]struct{}) (*ToolRecord, error) {
	if tn.Kind != canonical.KindObject {
		return nil, malformedDiscovery("tool entry is not a JSON object")
	}
	for _, k := range tn.Keys {
		if _, ok := toolMembers[k]; !ok {
			return nil, malformedDiscovery("unknown tool member")
		}
	}
	name, err := toolName(tn, lim)
	if err != nil {
		return nil, err
	}
	if _, dup := seen[name]; dup {
		return nil, mcperr.New(mcperr.ReasonDuplicateTool, "catalog.ingest", "duplicate tool name in one discovery result")
	}
	seen[name] = struct{}{}

	inputNode, err := requiredSchema(tn, "inputSchema", lim)
	if err != nil {
		return nil, err
	}
	outputNode, hasOutput, err := optionalSchema(tn, "outputSchema", lim)
	if err != nil {
		return nil, err
	}
	descHash, err := descriptiveHash(tn, lim)
	if err != nil {
		return nil, err
	}
	fp := Fingerprint{
		Server:            server.ID,
		Identity:          server.PinnedIdentity,
		Name:              name,
		InputSchemaHash:   canonical.HashNode(inputNode),
		HasOutputSchema:   hasOutput,
		DescriptiveHash:   descHash,
		CredentialProfile: server.CredentialProfile,
		Destination:       in.Destinations[name],
		FormatVersion:     fingerprintFormatVersion,
	}
	if hasOutput {
		fp.OutputSchemaHash = canonical.HashNode(outputNode)
	}
	return &ToolRecord{
		Key:          ToolKey{Server: server.ID, Name: name},
		Fingerprint:  fp,
		InputSchema:  inputNode,
		OutputSchema: outputNode,
	}, nil
}

// toolName extracts and validates the tool name: a non-empty, byte-stable ASCII
// token within MaxNameBytes drawn from the PR-1 method-token charset, with no
// control characters and no Unicode normalization or case folding.
func toolName(tn *canonical.Node, lim limits.CatalogLimits) (string, error) {
	nameNode, ok := tn.Get("name")
	if !ok || nameNode.Kind != canonical.KindString {
		return "", malformedDiscovery("tool missing string name")
	}
	name := nameNode.Str
	if name == "" {
		return "", malformedDiscovery("empty tool name")
	}
	if len(name) > lim.MaxNameBytes() {
		return "", mcperr.New(mcperr.ReasonResourceLimit, "catalog.ingest", "tool name length")
	}
	for i := 0; i < len(name); i++ {
		if name[i] >= 0x80 {
			return "", malformedDiscovery("non-ascii tool name")
		}
		if !isNameByte(name[i]) {
			return "", malformedDiscovery("invalid character in tool name")
		}
	}
	return name, nil
}

func isNameByte(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	case c == '/' || c == '_' || c == '-' || c == '.':
		return true
	default:
		return false
	}
}

// requiredSchema extracts a required object schema member and returns its
// schema-canonical node, enforcing the schema byte bound.
func requiredSchema(tn *canonical.Node, key string, lim limits.CatalogLimits) (*canonical.Node, error) {
	sn, ok := tn.Get(key)
	if !ok {
		return nil, malformedDiscovery("tool missing " + key)
	}
	if sn.Kind != canonical.KindObject {
		return nil, malformedDiscovery(key + " is not a JSON object")
	}
	canon := canonical.SchemaFromNode(sn)
	if len(canonical.Encode(canon)) > lim.MaxSchemaBytes() {
		return nil, mcperr.New(mcperr.ReasonResourceLimit, "catalog.ingest", key+" bytes")
	}
	return canon, nil
}

// optionalSchema extracts an optional object schema member. It returns
// (node, true, nil) when present, (nil, false, nil) when absent — the presence
// marker is load-bearing (absent ≠ present-empty).
func optionalSchema(tn *canonical.Node, key string, lim limits.CatalogLimits) (*canonical.Node, bool, error) {
	sn, ok := tn.Get(key)
	if !ok {
		return nil, false, nil
	}
	if sn.Kind != canonical.KindObject {
		return nil, false, malformedDiscovery(key + " is not a JSON object")
	}
	canon := canonical.SchemaFromNode(sn)
	if len(canonical.Encode(canon)) > lim.MaxSchemaBytes() {
		return nil, false, mcperr.New(mcperr.ReasonResourceLimit, "catalog.ingest", key+" bytes")
	}
	return canon, true, nil
}

// descriptiveHash folds the tool's human-facing metadata — normalized
// description, canonical annotations object, and normalized title — into one
// length-segmented SHA-256. Any content change in any of the three changes the
// hash (a semantic signal); cosmetic whitespace in description/title does not.
func descriptiveHash(tn *canonical.Node, lim limits.CatalogLimits) ([32]byte, error) {
	h := sha256.New()
	writeSeg := func(tag string, b []byte) {
		h.Write([]byte(tag))
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(b)))
		h.Write(n[:])
		h.Write(b)
	}
	desc, err := optionalText(tn, "description", lim.MaxDescriptionBytes())
	if err != nil {
		return [32]byte{}, err
	}
	writeSeg("d", []byte(desc))
	title, err := optionalText(tn, "title", lim.MaxDescriptionBytes())
	if err != nil {
		return [32]byte{}, err
	}
	writeSeg("t", []byte(title))
	if an, ok := tn.Get("annotations"); ok {
		if an.Kind != canonical.KindObject {
			return [32]byte{}, malformedDiscovery("annotations is not a JSON object")
		}
		enc := canonical.Encode(an)
		if len(enc) > lim.MaxSchemaBytes() {
			return [32]byte{}, mcperr.New(mcperr.ReasonResourceLimit, "catalog.ingest", "annotations bytes")
		}
		writeSeg("a", enc)
	} else {
		writeSeg("a", nil) // explicit absence marker (distinct from present-empty {})
	}
	var out [32]byte
	h.Sum(out[:0])
	return out, nil
}

// optionalText reads an optional string member and returns its whitespace-
// normalized form (empty string when the member is absent).
func optionalText(tn *canonical.Node, key string, maxBytes int) (string, error) {
	n, ok := tn.Get(key)
	if !ok {
		return "", nil
	}
	if n.Kind != canonical.KindString {
		return "", malformedDiscovery(key + " is not a string")
	}
	norm, err := canonical.NormalizeDescription(n.Str, maxBytes)
	if err != nil {
		return "", err
	}
	return norm, nil
}

// discoveryBounds derives the whole-result decode bounds from a CatalogLimits.
func discoveryBounds(lim limits.CatalogLimits) canonical.Bounds {
	return canonical.Bounds{
		MaxBytes:         lim.MaxDiscoveryBytes(),
		MaxDepth:         lim.MaxSchemaDepth(),
		MaxObjectMembers: lim.MaxObjectMembers(),
		MaxArrayElements: lim.MaxToolsPerServer() + lim.MaxArrayElements(),
		MaxStringBytes:   lim.MaxSchemaBytes(),
	}
}
