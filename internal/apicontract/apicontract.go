// Package apicontract is the durable enforcement core of the Culvert OpenAPI
// program. It is deliberately decoupled from package main: it operates on a
// plain []Route slice (supplied by the caller) plus two on-disk artifacts — the
// OpenAPI contract and the route-classification manifest — so its logic is
// unit-testable in isolation with fixtures and reused by the live-router gate in
// package main.
//
// The three enforcement surfaces:
//
//	LoadSpec      — parse + validate the OpenAPI document (Gate 1).
//	StyleLint     — organizational lint rules over the contract (Gate 2).
//	CheckCoverage — bijective route⇄manifest⇄spec coverage (Gate 3).
//	CheckExemptions — no expired route exemption survives (Gate 3, time axis).
//
// Everything is offline and Go-native (getkin/kin-openapi); no network, no Node,
// no external binary — it runs inside `go test`.
package apicontract

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/goccy/go-yaml"
)

// Route is a single registered admin-API route+method, as known to the live
// router. package main adapts its uiRoutes table into this shape.
type Route struct {
	Path    string
	Method  string // "GET" | "POST" | ... | "*" (MethodAny)
	Handler string
	Domain  string
	Public  bool
	MinRole string
	Muta    bool
	Audit   bool
}

// Operation is one spec operation (path × method).
type Operation struct {
	Path   string
	Method string
	Op     *openapi3.Operation
}

// Spec wraps a validated OpenAPI document.
type Spec struct {
	Doc  *openapi3.T
	Ops  []Operation
	Path string
}

// LoadSpec loads and validates the OpenAPI document (Gate 1: syntax, $ref
// resolution, schema correctness, duplicate operationId, security-scheme refs).
func LoadSpec(path string) (*Spec, error) {
	loader := openapi3.NewLoader()
	loader.IsExternalRefsAllowed = false
	doc, err := loader.LoadFromFile(path)
	if err != nil {
		return nil, fmt.Errorf("load %s: %w", path, err)
	}
	if err := doc.Validate(context.Background()); err != nil {
		return nil, fmt.Errorf("validate %s: %w", path, err)
	}
	s := &Spec{Doc: doc, Path: path}
	if doc.Paths != nil {
		for p, item := range doc.Paths.Map() {
			for method, op := range item.Operations() {
				s.Ops = append(s.Ops, Operation{Path: p, Method: strings.ToUpper(method), Op: op})
			}
		}
	}
	sort.Slice(s.Ops, func(i, j int) bool {
		if s.Ops[i].Path != s.Ops[j].Path {
			return s.Ops[i].Path < s.Ops[j].Path
		}
		return s.Ops[i].Method < s.Ops[j].Method
	})
	return s, nil
}

// Ext reads a string vendor-extension value from an operation.
func Ext(op *openapi3.Operation, key string) string { return extString(op.Extensions, key) }

// OpForRow returns the operation documenting this manifest row, or nil.
func (s *Spec) OpForRow(r ClassRow) *openapi3.Operation {
	for _, o := range s.Ops {
		if o.Path == r.specPath() && methodMatch(r.Method, o.Method) {
			return o.Op
		}
	}
	return nil
}

// FindOp returns the operation for a concrete method+path, or nil.
func (s *Spec) FindOp(method, path string) *openapi3.Operation {
	for _, o := range s.Ops {
		if o.Path == path && strings.EqualFold(o.Method, method) {
			return o.Op
		}
	}
	return nil
}

// ValidateJSONResponse validates a real handler's JSON response body against the
// operation's response schema for `status` (Gate 5). A missing operation or
// status is a hard error — the contract must describe what the handler returns.
func (s *Spec) ValidateJSONResponse(method, path string, status int, body []byte) error {
	op := s.FindOp(method, path)
	if op == nil {
		return fmt.Errorf("no operation %s %s in contract", method, path)
	}
	if op.Responses == nil {
		return fmt.Errorf("%s %s has no responses", method, path)
	}
	rr := op.Responses.Map()[fmt.Sprintf("%d", status)]
	if rr == nil || rr.Value == nil {
		return fmt.Errorf("%s %s does not document status %d", method, path, status)
	}
	mt := rr.Value.Content.Get("application/json")
	if mt == nil || mt.Schema == nil || mt.Schema.Value == nil {
		return fmt.Errorf("%s %s status %d has no application/json schema", method, path, status)
	}
	var v any
	if err := json.Unmarshal(body, &v); err != nil {
		return fmt.Errorf("response body is not valid JSON: %w", err)
	}
	return mt.Schema.Value.VisitJSON(v)
}

// ValidateJSONRequest validates a request body against the operation's
// application/json request schema (Gate 4).
func (s *Spec) ValidateJSONRequest(method, path string, body []byte) error {
	op := s.FindOp(method, path)
	if op == nil {
		return fmt.Errorf("no operation %s %s in contract", method, path)
	}
	if op.RequestBody == nil || op.RequestBody.Value == nil {
		return fmt.Errorf("%s %s documents no request body", method, path)
	}
	mt := op.RequestBody.Value.Content.Get("application/json")
	if mt == nil || mt.Schema == nil || mt.Schema.Value == nil {
		return fmt.Errorf("%s %s has no application/json request schema", method, path)
	}
	var v any
	if err := json.Unmarshal(body, &v); err != nil {
		return fmt.Errorf("request body is not valid JSON: %w", err)
	}
	return mt.Schema.Value.VisitJSON(v)
}

// ── Classification manifest ──────────────────────────────────────────────────

// Exemption records why a route is not (yet) in the contract.
type Exemption struct {
	Owner         string `yaml:"owner"`
	Reason        string `yaml:"reason"`
	SecurityClass string `yaml:"security_class"`
	Expires       string `yaml:"expires"`
}

// ClassRow is one classification manifest entry.
type ClassRow struct {
	Route         string `yaml:"route"`
	Method        string `yaml:"method"`
	Handler       string `yaml:"handler"`
	Domain        string `yaml:"domain"`
	Visibility    string `yaml:"visibility"`
	MinRole       string `yaml:"min_role"`
	Mutating      bool   `yaml:"mutating"`
	AuditExpected bool   `yaml:"audit_expected"`
	DangerLevel   string `yaml:"danger_level"`
	Documented    bool   `yaml:"documented"`
	OpenAPIPath   string `yaml:"openapi_path"` // optional; defaults to Route
	// ExtraOpenAPIPaths lists FURTHER contract paths served by the SAME
	// registered route + method (a prefix route whose handler dispatches on a
	// path suffix — e.g. GET /api/pac/profiles/ serves both
	// /api/pac/profiles/{name} and /api/pac/profiles/{name}/lifecycle). Each
	// must exist in the contract; each counts as documented by this row.
	ExtraOpenAPIPaths []string   `yaml:"openapi_extra_paths"`
	Exemption         *Exemption `yaml:"exemption"`
}

// specPath returns the path used to match this row against the OpenAPI contract.
func (r ClassRow) specPath() string {
	if r.OpenAPIPath != "" {
		return r.OpenAPIPath
	}
	return r.Route
}

// SpecPath is the exported path this row matches against the contract.
func (r ClassRow) SpecPath() string { return r.specPath() }

// Classification is the parsed route-classification manifest.
type Classification struct {
	Version                 int        `yaml:"version"`
	BaselineExemptionExpiry string     `yaml:"baseline_exemption_expiry"`
	Rows                    []ClassRow `yaml:"routes"`
}

// validVisibilities is the closed set of visibility classifications.
var validVisibilities = map[string]bool{
	"public-supported":           true,
	"admin-supported":            true,
	"appliance-internal":         true,
	"cluster-internal":           true,
	"agent-internal":             true,
	"debug":                      true,
	"health-ops":                 true,
	"intentionally-undocumented": true,
}

// LoadClassification parses the manifest (goccy/go-yaml resolves the YAML anchor
// used for the shared baseline expiry).
func LoadClassification(path string) (*Classification, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Classification
	if err := yaml.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &c, nil
}

// ── Gate 3: coverage ─────────────────────────────────────────────────────────

func key(path, method string) string { return path + "\x00" + strings.ToUpper(method) }

func methodMatch(rowMethod, specMethod string) bool {
	if rowMethod == "*" {
		return true
	}
	return strings.EqualFold(rowMethod, specMethod)
}

// CheckCoverage enforces the bijection route ⇄ manifest and the coverage manifest
// ⇄ spec. It returns a sorted list of human-readable violations (empty == pass).
//
//  1. every live route+method has exactly one manifest row (no unclassified route)
//  2. every manifest row maps to a live route+method (no stale row)
//  3. every documented row appears as a spec operation
//  4. every spec operation maps to a documented row (no phantom operation)
//  5. row/exemption/documented consistency
//
// The time axis (expired exemptions) is CheckExemptions.
func CheckCoverage(routes []Route, spec *Spec, c *Classification) []string {
	var v []string

	rowByKey := map[string]ClassRow{}
	rowSeen := map[string]int{}
	for i := range c.Rows {
		k := key(c.Rows[i].Route, c.Rows[i].Method)
		rowByKey[k] = c.Rows[i]
		rowSeen[k]++
	}
	for k, n := range rowSeen {
		if n > 1 {
			v = append(v, fmt.Sprintf("classification: duplicate row for %s (x%d)", strings.ReplaceAll(k, "\x00", " "), n))
		}
	}

	routeByKey := map[string]Route{}
	for i := range routes {
		routeByKey[key(routes[i].Path, routes[i].Method)] = routes[i]
	}

	v = append(v, coverageRouteChecks(routes, c, rowByKey, routeByKey)...)
	v = append(v, coverageRowConsistency(c)...)
	v = append(v, coverageSpecChecks(spec, c)...)

	sort.Strings(v)
	return v
}

// coverageRouteChecks enforces the route⇄manifest bijection (checks 1 & 2) plus
// the RBAC/mutating/audit drift binding that ties the manifest to uiRoutes
// (itself bound to the handler by C1.5), so the manifest cannot silently diverge
// from runtime authorization.
func coverageRouteChecks(routes []Route, c *Classification, rowByKey map[string]ClassRow, routeByKey map[string]Route) []string {
	var v []string
	for i := range routes {
		r := &routes[i]
		if _, ok := rowByKey[key(r.Path, r.Method)]; !ok {
			v = append(v, fmt.Sprintf("UNCLASSIFIED ROUTE: %s %s (%s) — add a row to api/route-classification.yaml (document it or exempt it)", r.Method, r.Path, r.Handler))
		}
	}
	for i := range c.Rows {
		r := &c.Rows[i]
		lr, ok := routeByKey[key(r.Route, r.Method)]
		if !ok {
			v = append(v, fmt.Sprintf("STALE CLASSIFICATION: %s %s no longer maps to a registered route — remove the row", r.Method, r.Route))
			continue
		}
		if r.MinRole != lr.MinRole {
			v = append(v, fmt.Sprintf("ROLE DRIFT: %s %s manifest min_role=%q but router MinRole=%q", r.Method, r.Route, r.MinRole, lr.MinRole))
		}
		if r.Mutating != lr.Muta {
			v = append(v, fmt.Sprintf("MUTATING DRIFT: %s %s manifest mutating=%v but router=%v", r.Method, r.Route, r.Mutating, lr.Muta))
		}
		if r.AuditExpected != lr.Audit {
			v = append(v, fmt.Sprintf("AUDIT DRIFT: %s %s manifest audit_expected=%v but router=%v", r.Method, r.Route, r.AuditExpected, lr.Audit))
		}
	}
	return v
}

// coverageRowConsistency checks per-row visibility + documented/exemption
// consistency + exemption completeness (check 5).
func coverageRowConsistency(c *Classification) []string {
	var v []string
	for i := range c.Rows {
		r := &c.Rows[i]
		if r.Visibility == "" || !validVisibilities[r.Visibility] {
			v = append(v, fmt.Sprintf("classification: %s %s has invalid visibility %q", r.Method, r.Route, r.Visibility))
		}
		if r.Documented && r.Exemption != nil {
			v = append(v, fmt.Sprintf("classification: %s %s is documented but also carries an exemption — remove the exemption", r.Method, r.Route))
		}
		if !r.Documented && r.Exemption == nil {
			v = append(v, fmt.Sprintf("classification: %s %s is neither documented nor exempt — add an exemption{owner,reason,security_class,expires} or document it", r.Method, r.Route))
		}
		v = append(v, exemptionCompleteness(r)...)
	}
	return v
}

func exemptionCompleteness(r *ClassRow) []string {
	if r.Exemption == nil {
		return nil
	}
	var v []string
	if r.Exemption.Owner == "" {
		v = append(v, fmt.Sprintf("classification: %s %s exemption missing owner", r.Method, r.Route))
	}
	if r.Exemption.Reason == "" {
		v = append(v, fmt.Sprintf("classification: %s %s exemption missing reason", r.Method, r.Route))
	}
	if r.Exemption.SecurityClass == "" {
		v = append(v, fmt.Sprintf("classification: %s %s exemption missing security_class", r.Method, r.Route))
	}
	if r.Exemption.Expires == "" {
		v = append(v, fmt.Sprintf("classification: %s %s exemption missing expires", r.Method, r.Route))
	}
	return v
}

// coverageSpecChecks enforces documented⊆spec (check 3) and spec⊆documented, the
// no-phantom-operation guard (check 4).
func coverageSpecChecks(spec *Spec, c *Classification) []string {
	var v []string
	for i := range c.Rows {
		r := &c.Rows[i]
		if !r.Documented {
			continue
		}
		if !specHasOp(spec, r.specPath(), r.Method) {
			v = append(v, fmt.Sprintf("DOCUMENTED-BUT-MISSING: %s %s is marked documented but has no matching OpenAPI operation", r.Method, r.specPath()))
		}
		for _, extra := range r.ExtraOpenAPIPaths {
			if !specHasOp(spec, extra, r.Method) {
				v = append(v, fmt.Sprintf("DOCUMENTED-BUT-MISSING: %s %s (openapi_extra_paths of %s) is marked documented but has no matching OpenAPI operation", r.Method, extra, r.Route))
			}
		}
	}
	for _, op := range spec.Ops {
		if !documentedRowFor(c, op.Path, op.Method) {
			v = append(v, fmt.Sprintf("PHANTOM OPERATION: %s %s (operationId=%s) is in the contract but maps to no documented route", op.Method, op.Path, op.Op.OperationID))
		}
	}
	return v
}

// specHasOp reports whether the contract carries an operation at path whose
// method matches (row wildcard `*` matches any).
func specHasOp(spec *Spec, path, rowMethod string) bool {
	for _, op := range spec.Ops {
		if op.Path == path && methodMatch(rowMethod, op.Method) {
			return true
		}
	}
	return false
}

// documentedRowFor reports whether a documented manifest row covers the given
// spec operation path+method.
func documentedRowFor(c *Classification, specPath, specMethod string) bool {
	for i := range c.Rows {
		r := &c.Rows[i]
		if !r.Documented || !methodMatch(r.Method, specMethod) {
			continue
		}
		if specPath == r.specPath() {
			return true
		}
		for _, extra := range r.ExtraOpenAPIPaths {
			if specPath == extra {
				return true
			}
		}
	}
	return false
}

// MaxExemptionHorizonDays caps how far in the future an exemption may be set, so
// a route cannot dodge documentation indefinitely by pinning a far-future date.
const MaxExemptionHorizonDays = 270

// CheckExemptions fails when any exemption has expired OR is set beyond the
// maximum horizon relative to `now` (Gate 3, time axis). Expiry is YYYY-MM-DD and
// the route stays valid THROUGH the expiry date (the +24h makes the date
// inclusive); it fails the day after.
func CheckExemptions(c *Classification, now time.Time) []string {
	var v []string
	horizon := now.AddDate(0, 0, MaxExemptionHorizonDays)
	for i := range c.Rows {
		r := &c.Rows[i]
		if r.Exemption == nil {
			continue
		}
		exp, err := time.Parse("2006-01-02", strings.TrimSpace(r.Exemption.Expires))
		if err != nil {
			v = append(v, fmt.Sprintf("EXEMPTION PARSE: %s %s has unparseable expires %q (want YYYY-MM-DD)", r.Method, r.Route, r.Exemption.Expires))
			continue
		}
		if !now.Before(exp.Add(24 * time.Hour)) {
			v = append(v, fmt.Sprintf("EXPIRED EXEMPTION: %s %s expired %s (owner %s) — document the route or renew the exemption with justification", r.Method, r.Route, r.Exemption.Expires, r.Exemption.Owner))
			continue
		}
		if exp.After(horizon) {
			v = append(v, fmt.Sprintf("EXEMPTION TOO FAR: %s %s expires %s — exceeds the %d-day horizon; exemptions may not defer documentation indefinitely", r.Method, r.Route, r.Exemption.Expires, MaxExemptionHorizonDays))
		}
	}
	sort.Strings(v)
	return v
}

// ── Gate 2: organizational style lint ────────────────────────────────────────

func extString(ext map[string]any, key string) string {
	v, ok := ext[key]
	if !ok {
		return ""
	}
	switch t := v.(type) {
	case string:
		return t
	case bool:
		// YAML booleans (e.g. `x-culvert-sensitive: true`) must compare as the
		// string "true"/"false" — without this the sensitive-schema lint is a
		// no-op (the extension is authored as a YAML boolean, not a string).
		if t {
			return "true"
		}
		return "false"
	case json.RawMessage:
		var s string
		if json.Unmarshal(t, &s) == nil {
			return s
		}
	default:
		b, err := json.Marshal(v)
		if err == nil {
			var s string
			if json.Unmarshal(b, &s) == nil {
				return s
			}
		}
	}
	return ""
}

var (
	validVisibilityExt = map[string]bool{"public-supported": true, "admin-supported": true, "appliance-internal": true, "cluster-internal": true, "agent-internal": true, "debug": true, "health-ops": true}
	validPermission    = map[string]bool{"public": true, "viewer": true, "operator": true, "admin": true}
	validDanger        = map[string]bool{"none": true, "low": true, "medium": true, "high": true}
)

// StyleLint enforces the organizational API style rules over the contract
// (Gate 2). Returns a sorted list of violations (empty == pass).
func StyleLint(spec *Spec) []string {
	var v []string
	seenOpID := map[string]string{}
	for _, o := range spec.Ops {
		v = append(v, lintOperation(o, seenOpID)...)
	}
	v = append(v, lintSensitiveSchemas(spec)...)
	sort.Strings(v)
	return v
}

// lintOperation applies the per-operation style rules (identity, prose, security,
// responses, and required x-culvert-* metadata). seenOpID is shared across calls
// to detect duplicate operationIds.
func lintOperation(o Operation, seenOpID map[string]string) []string {
	op := o.Op
	where := fmt.Sprintf("%s %s", o.Method, o.Path)
	var v []string

	if op.OperationID == "" {
		v = append(v, fmt.Sprintf("%s: missing operationId", where))
	} else if prev, dup := seenOpID[op.OperationID]; dup {
		v = append(v, fmt.Sprintf("%s: duplicate operationId %q (also %s)", where, op.OperationID, prev))
	} else {
		seenOpID[op.OperationID] = where
	}

	if strings.TrimSpace(op.Summary) == "" {
		v = append(v, fmt.Sprintf("%s: missing summary", where))
	}
	if strings.TrimSpace(op.Description) == "" {
		v = append(v, fmt.Sprintf("%s: missing description", where))
	}
	if len(op.Tags) == 0 {
		v = append(v, fmt.Sprintf("%s: missing tags", where))
	}
	if op.Security == nil {
		v = append(v, fmt.Sprintf("%s: security not declared (use `security: []` for public routes)", where))
	}

	v = append(v, lintResponses(op, where)...)
	v = append(v, lintExtensions(o, where)...)
	return v
}

// lintResponses requires at least one 2xx success and one 4xx/5xx error.
func lintResponses(op *openapi3.Operation, where string) []string {
	has2xx, hasErr := false, false
	if op.Responses != nil {
		for code := range op.Responses.Map() {
			switch {
			case strings.HasPrefix(code, "2"):
				has2xx = true
			case strings.HasPrefix(code, "4"), strings.HasPrefix(code, "5"):
				hasErr = true
			}
		}
	}
	var v []string
	if !has2xx {
		v = append(v, fmt.Sprintf("%s: no 2xx success response documented", where))
	}
	if !hasErr {
		v = append(v, fmt.Sprintf("%s: no 4xx/5xx error response documented", where))
	}
	return v
}

// lintExtensions requires the x-culvert-* metadata, with stricter rules for
// mutating/destructive operations.
func lintExtensions(o Operation, where string) []string {
	ext := o.Op.Extensions
	var v []string
	if vis := extString(ext, "x-culvert-visibility"); !validVisibilityExt[vis] {
		v = append(v, fmt.Sprintf("%s: missing/invalid x-culvert-visibility (%q)", where, vis))
	}
	if perm := extString(ext, "x-culvert-permission"); !validPermission[perm] {
		v = append(v, fmt.Sprintf("%s: missing/invalid x-culvert-permission (%q)", where, perm))
	}
	if extString(ext, "x-culvert-stability") == "" {
		v = append(v, fmt.Sprintf("%s: missing x-culvert-stability", where))
	}
	if extString(ext, "x-culvert-introduced-version") == "" {
		v = append(v, fmt.Sprintf("%s: missing x-culvert-introduced-version", where))
	}
	// Stricter rules for mutating/destructive operations. A non-GET op must
	// declare a danger level; an audit event is required only when the op is
	// actually state-changing (danger-level != "none") — pure analysis POSTs
	// (simulate/test/analyze) legitimately neither mutate nor audit.
	if o.Method != "GET" && o.Method != "HEAD" && o.Method != "OPTIONS" {
		danger := extString(ext, "x-culvert-danger-level")
		if !validDanger[danger] {
			v = append(v, fmt.Sprintf("%s: mutating op missing/invalid x-culvert-danger-level (%q)", where, danger))
		}
		if danger != "none" && extString(ext, "x-culvert-audit-event") == "" {
			v = append(v, fmt.Sprintf("%s: state-changing op missing x-culvert-audit-event", where))
		}
	}
	return v
}

// lintSensitiveSchemas flags any x-culvert-sensitive schema that silently allows
// additionalProperties:true without an x-culvert-open-justification.
func lintSensitiveSchemas(spec *Spec) []string {
	if spec.Doc.Components == nil {
		return nil
	}
	var v []string
	for name, ref := range spec.Doc.Components.Schemas {
		if ref == nil || ref.Value == nil {
			continue
		}
		sch := ref.Value
		if extString(sch.Extensions, "x-culvert-sensitive") != "true" {
			continue
		}
		openAP := sch.AdditionalProperties.Has != nil && *sch.AdditionalProperties.Has
		justified := extString(sch.Extensions, "x-culvert-open-justification") != ""
		if openAP && !justified {
			v = append(v, fmt.Sprintf("schema %s: x-culvert-sensitive with additionalProperties:true and no x-culvert-open-justification", name))
		}
	}
	return v
}
