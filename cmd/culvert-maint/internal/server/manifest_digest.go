// Structural selection of the target manifest digest from
// `docker manifest inspect --verbose` output (D1.6c upgrade-apply).
//
// WHY this exists (correctness): the apply flow must resolve a requested
// TAG to a single, pullable `repo@sha256:<digest>` pin. The naive approach
// — regex-scrape every `sha256:…` token out of the verbose JSON, sort, and
// take the first — is WRONG for two reasons:
//
//  1. `manifest inspect --verbose` embeds the FULL per-platform manifest
//     bodies (SchemaV2Manifest/OCIManifest), whose `config.digest` and
//     `layers[].digest` are also `sha256:…` tokens. The lexicographically
//     smallest token is therefore very often a LAYER or CONFIG blob digest,
//     not a manifest descriptor — pulling `repo@sha256:<layer-digest>`
//     fails outright.
//  2. Even restricted to descriptor digests, a multi-arch image yields one
//     per platform; picking an arbitrary one can pin the WRONG architecture.
//
// This parser reads the JSON structurally, considers ONLY the top-level
// `Descriptor.digest` of each entry, and selects the one matching THIS
// host's platform. It fails CLOSED on ambiguity (multiple host-platform
// matches, or none) rather than pinning an arbitrary digest — a destructive
// host op must never guess which image it is about to run.
package server

import (
	"encoding/json"
	"fmt"
	"runtime"
)

// manifestVerboseEntry is the narrow projection of one element of
// `docker manifest inspect --verbose` output we depend on. The command
// emits a single object for a single-arch image and a JSON array for a
// multi-arch (manifest-list) image; resolveTargetManifestDigest handles
// both shapes. Fields beyond these are ignored (and deliberately never
// logged — the verbose JSON carries image metadata).
type manifestVerboseEntry struct {
	Descriptor struct {
		Digest   string `json:"digest"`
		Platform struct {
			OS           string `json:"os"`
			Architecture string `json:"architecture"`
			Variant      string `json:"variant"`
		} `json:"platform"`
	} `json:"Descriptor"`
}

// resolveTargetManifestDigest parses `docker manifest inspect --verbose`
// stdout and returns the single manifest descriptor digest (sha256:<64hex>)
// to pin for THIS host. It fails closed when it cannot resolve exactly one:
//   - no well-formed descriptor digest present,
//   - a multi-arch list with zero or more-than-one entry matching the host
//     platform (runtime.GOOS/GOARCH).
//
// A single-entry (single-arch) result is used regardless of platform — the
// registry offered exactly one image and there is nothing to disambiguate.
func resolveTargetManifestDigest(stdout []byte) (string, error) {
	entries, err := parseManifestVerbose(stdout)
	if err != nil {
		return "", err
	}

	// Keep only entries carrying a well-formed manifest descriptor digest.
	valid := make([]manifestVerboseEntry, 0, len(entries))
	for i := range entries {
		if isFullDigest(entries[i].Descriptor.Digest) {
			valid = append(valid, entries[i])
		}
	}
	switch len(valid) {
	case 0:
		return "", fmt.Errorf("no manifest descriptor digest in inspect output")
	case 1:
		// Single-arch (or a registry that offered exactly one manifest):
		// unambiguous, platform is irrelevant.
		return valid[0].Descriptor.Digest, nil
	}

	// Multi-arch: disambiguate strictly by this host's platform. Anything
	// other than exactly one match fails closed.
	matches := make([]string, 0, 1)
	for i := range valid {
		p := valid[i].Descriptor.Platform
		if p.OS == runtime.GOOS && p.Architecture == runtime.GOARCH {
			matches = append(matches, valid[i].Descriptor.Digest)
		}
	}
	switch len(matches) {
	case 1:
		return matches[0], nil
	case 0:
		return "", fmt.Errorf("no manifest descriptor matches host platform %s/%s (%d platform(s) offered)",
			runtime.GOOS, runtime.GOARCH, len(valid))
	default:
		return "", fmt.Errorf("ambiguous target: %d manifest descriptors match host platform %s/%s",
			len(matches), runtime.GOOS, runtime.GOARCH)
	}
}

// parseManifestVerbose decodes stdout as either a JSON array of entries
// (multi-arch) or a single entry object (single-arch), returning a uniform
// slice. An empty/whitespace body or a decode failure is an error (the
// caller fails the op — we cannot pin what we cannot parse).
func parseManifestVerbose(stdout []byte) ([]manifestVerboseEntry, error) {
	var arr []manifestVerboseEntry
	if err := json.Unmarshal(stdout, &arr); err == nil {
		return arr, nil
	}
	var one manifestVerboseEntry
	if err := json.Unmarshal(stdout, &one); err != nil {
		return nil, fmt.Errorf("parse manifest inspect output: %w", err)
	}
	return []manifestVerboseEntry{one}, nil
}

// isFullDigest reports whether s is exactly a `sha256:<64 lowercase hex>`
// content digest (the whole string, not a substring). digestRE is used with
// FindString elsewhere for substring extraction; here we need a full-string
// match so a partial/garbage descriptor value is rejected.
func isFullDigest(s string) bool {
	return s != "" && digestRE.FindString(s) == s
}
