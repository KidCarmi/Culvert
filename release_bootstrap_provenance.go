// Bootstrap provenance — make the appliance able to prove which signed-catalog
// decision provisioned it.
//
// `culvert bootstrap-resolve --out` writes the full decision (immutable digest,
// catalog_version, generated_at/expires_at, trust scheme, resolved channel) at
// install time. That record lives on the HOST filesystem, which the running
// container cannot read. The installer therefore drops a copy into /data
// (scripts/install.sh: persist_bootstrap_decision) after the first `docker compose
// up`, and this file surfaces it READ-ONLY on GET /api/releases so an operator (and
// incident response) can answer "which digest/catalog_version/trust-scheme
// bootstrapped this fleet member?" without host/SSH access — the GUI-parity contract.
package main

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
)

// bootstrapDecisionFile is the container-readable provenance record under dataDir.
const bootstrapDecisionFile = "bootstrap_decision.json"

// maxBootstrapDecisionBytes bounds the (trusted-but-defensive) read.
const maxBootstrapDecisionBytes = 64 << 10

// addBootstrapProvenance folds the persisted bootstrap decision into an
// /api/releases response under "bootstrap", when present and parseable. Best-effort:
// an absent / oversize / malformed record is silently omitted — a host provisioned
// before this feature, or via an explicit CULVERT_PROXY_SEED_REF break-glass, simply
// has no record. Independent of the currently-published catalog.
func addBootstrapProvenance(out map[string]any) {
	if dataDir == "" {
		return
	}
	// Fixed filename under the trusted data dir (not user input); bounded read.
	f, err := os.Open(filepath.Join(dataDir, bootstrapDecisionFile)) // #nosec G304 -- fixed name under trusted dataDir
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, maxBootstrapDecisionBytes+1))
	if err != nil || len(b) == 0 || len(b) > maxBootstrapDecisionBytes {
		return
	}
	var d bootstrapDecision
	if json.Unmarshal(b, &d) != nil || d.ImageRef == "" {
		return
	}
	out["bootstrap"] = d
}
