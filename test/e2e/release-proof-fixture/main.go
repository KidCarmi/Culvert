// Command release-proof-fixture creates short-lived, locally trusted evidence
// for disposable integration tests. It never saves its ephemeral signing key.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

type refs []string

func (r *refs) String() string     { return strings.Join(*r, ",") }
func (r *refs) Set(s string) error { *r = append(*r, s); return nil }

type evidence struct {
	ReleaseID string `json:"release_id"`
	Index     []byte `json:"index"`
	Signature []byte `json:"signature"`
	Manifest  []byte `json:"manifest"`
}

type entry struct {
	ReleaseID      string `json:"release_id"`
	VersionID      string `json:"version_id"`
	ManifestRef    string `json:"manifest_ref"`
	ManifestSHA256 string `json:"manifest_sha256"`
}

var labelPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)
var refPattern = regexp.MustCompile(`^([a-zA-Z0-9][a-zA-Z0-9._:/-]{0,254})@(sha256:[a-f0-9]{64})$`)

func parseRefs(args []string) (map[string]string, error) {
	if len(args) == 0 || len(args) > 32 {
		return nil, errors.New("require 1..32 labelled refs")
	}
	labels := make(map[string]string)
	repo := ""
	for _, arg := range args {
		label, ref, ok := strings.Cut(arg, "=")
		parts := refPattern.FindStringSubmatch(ref)
		if !ok || !labelPattern.MatchString(label) || len(parts) != 3 {
			return nil, errors.New("invalid label or pinned image reference")
		}
		if _, exists := labels[label]; exists {
			return nil, errors.New("duplicate label")
		}
		image := parts[1][strings.LastIndex(parts[1], "/")+1:]
		if image == "" || strings.Contains(image, ":") || strings.Contains(parts[1], "//") {
			return nil, errors.New("invalid image repository")
		}
		if repo != "" && repo != parts[1] {
			return nil, errors.New("references must share a repository")
		}
		repo = parts[1]
		labels[label] = ref
	}
	return labels, nil
}

func fixture(labels map[string]string, now time.Time) (map[string][]byte, error) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	unique := make(map[string]bool)
	for _, ref := range labels {
		unique[ref] = true
	}
	ordered := make([]string, 0, len(unique))
	for ref := range unique {
		ordered = append(ordered, ref)
	}
	sort.Strings(ordered)
	manifests := make(map[string][]byte)
	entries := make([]entry, 0, len(ordered))
	for i, ref := range ordered {
		repo, digest, _ := strings.Cut(ref, "@")
		id, version := fmt.Sprintf("lab-%d", i+1), fmt.Sprintf("1.0.%d", i+1)
		raw, marshalErr := json.Marshal(map[string]any{"schema_version": 1, "release_id": id, "version_id": version,
			"image": map[string]string{"repo": repo, "list_digest": digest}})
		if marshalErr != nil {
			return nil, marshalErr
		}
		sum := sha256.Sum256(raw)
		manifests[ref] = raw
		entries = append(entries, entry{id, version, id + ".json", hex.EncodeToString(sum[:])})
	}
	index, err := json.Marshal(map[string]any{"schema_version": 1, "catalog_version": 1,
		"generated_at": now.UTC().Format(time.RFC3339), "expires_at": now.Add(24 * time.Hour).UTC().Format(time.RFC3339), "releases": entries})
	if err != nil {
		return nil, err
	}
	signature, err := json.Marshal(map[string]any{"schema_version": 1, "alg": "ed25519", "key_id": "lab-ephemeral",
		"sig": base64.StdEncoding.EncodeToString(ed25519.Sign(private, index))})
	if err != nil {
		return nil, err
	}
	proofs := make(map[string]evidence)
	for i, ref := range ordered {
		proofs[ref] = evidence{entries[i].ReleaseID, index, signature, manifests[ref]}
	}
	files := make(map[string][]byte)
	files["keyring.json"], err = json.Marshal(map[string]string{"lab-ephemeral": base64.StdEncoding.EncodeToString(public)})
	if err != nil {
		return nil, err
	}
	files["proofs.json"], err = json.Marshal(proofs)
	if err != nil {
		return nil, err
	}
	for label, ref := range labels {
		files["proof-"+label+".json"], err = json.Marshal(proofs[ref])
		if err != nil {
			return nil, err
		}
	}
	return files, nil
}

func writeFixture(output string, files map[string][]byte) error {
	// Require a new directory, never overwrite an earlier run's trust/evidence.
	if err := os.Mkdir(output, 0o700); err != nil {
		return err
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(output, name), append(data, '\n'), 0o600); err != nil {
			return err
		}
	}
	return nil
}

func run(args []string) error {
	flags := flag.NewFlagSet("release-proof-fixture", flag.ContinueOnError)
	output := flags.String("output", "", "new output directory for public trust and evidence")
	var labelled refs
	flags.Var(&labelled, "ref", "repeat label=repository@sha256:digest")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *output == "" || len(flags.Args()) != 0 {
		return errors.New("output directory and labelled refs required")
	}
	labels, err := parseRefs(labelled)
	if err != nil {
		return err
	}
	files, err := fixture(labels, time.Now())
	if err != nil {
		return err
	}
	return writeFixture(*output, files)
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "release proof fixture failed:", err)
		os.Exit(1)
	}
}
