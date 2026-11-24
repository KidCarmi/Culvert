//go:build policy_pathdiff

// Package pathdiffgen generates inputs for the cross-path policy differential
// (policy_pathdiff_test.go) and holds its small independent reference.
//
// It is verification tooling only. Everything is behind the policy_pathdiff
// build tag, so neither `go build ./...` nor `go test ./...` compiles it.
//
// Independence rule: this package imports the standard library only and never
// calls, copies or links the production host normaliser, matcher or evaluator.
// TestIndependence enforces the import half. The generator knows the documented
// rule fields and a generic catalogue of spelling perturbations; it encodes no
// expectation about how production treats any of them.
//
// The reference is deliberately narrow. It states which pairs of spellings name
// the same destination under RFC 3986 section 3.2.2, RFC 4343 and RFC 5952, and
// what a first-match walk decides for rules whose conditions are plain literals.
// Wherever those sources do not settle a question it answers Unspecified, and
// the differential reports the product's behaviour instead of asserting it.
package pathdiffgen
