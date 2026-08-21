// Fresh-install catalog bootstrap resolver (`culvert bootstrap-resolve`).
//
// This subcommand is the INSTALLER-SIDE half of the release-catalog trust
// boundary. It makes the signed catalog the SOLE release authority for a fresh
// install, exactly as it already is for day-2 updates — eliminating the legacy
// "enumerate GHCR tags and pick the highest semver" path that installed the
// stale, pre-`/app/deploy` image `0.0.238` on a clean EC2 host.
//
// Trust is NOT reimplemented here. The subcommand reuses the identical runtime
// verifier the appliance uses at startup (release_catalog_verify.go /
// release_catalog_http.go / release_catalog_freshness.go): the baked ed25519
// roots ∪ operator roots, the baked Sigstore trusted root + pinned keyless
// identity, the two-phase SSRF-guarded HTTP fetch, and the freshness +
// anti-rollback + replay gates. The installer shell performs NO cryptography and
// NO JSON trust parsing — it only forwards inputs, runs this verified binary, and
// consumes the strict machine-readable decision on stdout.
//
// The binary that carries this subcommand is itself a signed release asset
// (`culvert-linux-<arch>` + `.sigstore.json`), and the installer cosign verify-blob's
// it against the SAME pinned release identity BEFORE executing it
// (scripts/install.sh: verify_bootstrap_verifier). So the whole chain — verifier
// binary, catalog, and resolved image — is signature-gated under one trust policy
// that cannot drift from the runtime (TestReleaseIdentitySSOT +
// TestInstaller_VerifierIsCosignVerified + bootstrap_resolve_test.go pin this).
// CATALOG and RESOLVED-IMAGE trust is fully enforced here (signature + freshness +
// rollback, baked roots + pinned identity — the SAME functions runtime uses).
//
// Note: this subcommand is inert on a non-official build (empty baked ed25519 roots
// AND empty Sigstore embed ⇒ enforce with no trusted scheme ⇒ fail closed); the
// installer always downloads the official signed release asset to run it.
//
// Contract: on SUCCESS a single JSON object (the install decision) is written to
// stdout and the process exits 0. On ANY failure a diagnostic is written to
// stderr and the process exits non-zero with an EMPTY stdout — fail closed. The
// installer treats a non-zero exit as "no trusted decision" and MUST NOT fall
// back to tag enumeration.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// bootstrapDecisionSchema is the schema_version of the emitted decision. The
// installer pins this so an older installer never silently misreads a newer,
// differently-shaped decision.
const bootstrapDecisionSchema = 1

// bootstrapResolveDefaultTimeout bounds the whole fetch+verify+resolve cycle.
const bootstrapResolveDefaultTimeout = 45 * time.Second

// bootstrapDecision is the machine-readable install decision printed to stdout on
// success. Field names are a stable wire contract consumed by scripts/install.sh.
type bootstrapDecision struct {
	SchemaVersion  int    `json:"schema_version"`
	InstallChannel string `json:"install_channel"` // the requested channel label (e.g. "stable")
	CatalogChannel string `json:"catalog_channel"` // the resolved catalog channel (e.g. "recommended")
	Repo           string `json:"repo"`            // bare image repo (allowlist-checked)
	ImageRef       string `json:"image_ref"`       // repo@sha256:<64hex> — the ONLY thing to pull
	Digest         string `json:"digest"`          // sha256:<64hex>
	ReleaseID      string `json:"release_id"`
	VersionID      string `json:"version_id"`
	Severity       string `json:"severity"`
	CatalogVersion int    `json:"catalog_version"`
	GeneratedAt    string `json:"generated_at"` // RFC3339 UTC
	ExpiresAt      string `json:"expires_at"`   // RFC3339 UTC
	TrustSchemes   string `json:"trust_schemes"`
	CatalogOrigin  string `json:"catalog_origin"` // host only (never a credentialed URL)
}

// maybeRunBootstrapResolve intercepts `culvert bootstrap-resolve ...` at the very
// top of main(), BEFORE the global flag set is defined. It is a positional
// subcommand, not a flag, so it must be dispatched before flag.Parse. On a match
// it runs to completion and exits the process; otherwise it returns and normal
// startup proceeds.
func maybeRunBootstrapResolve(argv []string) {
	if len(argv) < 2 || argv[1] != "bootstrap-resolve" {
		return
	}
	// Route trust-code diagnostics to STDERR so stdout stays pure JSON. The verify
	// path nil-guards logger, but a real logger surfaces useful SSRF/verify detail.
	if logger == nil {
		logger = log.New(os.Stderr, "", 0)
	}
	os.Exit(runBootstrapResolve(argv[2:], os.Stdout, os.Stderr))
}

// runBootstrapResolve parses the subcommand flags, resolves the trust config from
// the environment (identically to runtime startup), and runs the resolve core. It
// returns a process exit code: 0 on a printed decision, non-zero on any failure.
func runBootstrapResolve(argv []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("bootstrap-resolve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	channelFlag := fs.String("channel", "stable", "install channel: stable|lts|critical (stable ⇒ the catalog 'recommended' channel)")
	catalogURLFlag := fs.String("catalog-url", "", "catalog origin override (default: $"+envReleaseCatalogURL+" or the baked canonical origin)")
	proxyRepoFlag := fs.String("proxy-repo", "", "expected image repo allowlist (default: $"+envReleaseProxyRepo+" or the baked default)")
	dataDirFlag := fs.String("data-dir", "", "appliance data dir; its release_catalog_state.json is consulted read-only for the anti-rollback floor (optional)")
	stageDirFlag := fs.String("stage-dir", "", "parent dir for the temp staging dir (default: OS temp)")
	timeoutFlag := fs.Duration("timeout", bootstrapResolveDefaultTimeout, "overall fetch+verify+resolve timeout")
	// --print selects what goes to stdout so the installer NEVER parses JSON: a
	// scalar field is emitted verbatim by the trusted binary. --out additionally
	// writes the full decision JSON to a file (for the appliance's bootstrap record).
	printFlag := fs.String("print", "json", "stdout content: json | image_ref | digest | version_id | repo | catalog_version")
	outFlag := fs.String("out", "", "also write the full decision JSON to this file (0600)")
	if err := fs.Parse(argv); err != nil {
		return 2 // flag package already wrote usage to stderr
	}
	if !validBootstrapPrint(*printFlag) {
		bfprintf(stderr, "bootstrap-resolve: --print %q is not one of json|image_ref|digest|version_id|repo|catalog_version\n", *printFlag)
		return 2
	}

	// Trust config + origin are resolved by helpers (identical inputs to runtime
	// startup); each fails closed with a stderr message and ok=false.
	trust, keys, sigActive, ok := resolveBootstrapTrust(stderr)
	if !ok {
		return 1
	}
	catURL, originSource, ok := resolveBootstrapOrigin(*catalogURLFlag, stderr)
	if !ok {
		return 1
	}
	channel, err := mapInstallChannel(*channelFlag)
	if err != nil {
		bfprintf(stderr, "bootstrap-resolve: %v\n", err)
		return 1
	}

	statePath := ""
	if dd := strings.TrimSpace(*dataDirFlag); dd != "" {
		statePath = filepath.Join(dd, "release_catalog_state.json")
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeoutFlag)
	defer cancel()

	decision, err := bootstrapResolve(ctx, bootstrapResolveOpts{
		catalogURL:     catURL,
		originSource:   originSource,
		trust:          trust,
		channel:        channel,
		installChannel: strings.ToLower(strings.TrimSpace(*channelFlag)),
		proxyRepo:      resolveBootstrapProxyRepo(*proxyRepoFlag),
		statePath:      statePath,
		stageBase:      strings.TrimSpace(*stageDirFlag),
		trustSchemes:   trustSchemesOf(keys, sigActive),
	})
	if err != nil {
		bfprintf(stderr, "bootstrap-resolve: %v\n", err)
		return 1
	}
	return emitBootstrapDecision(decision, *printFlag, *outFlag, stdout, stderr)
}

// bfprintf / bfprintln are errcheck-quiet diagnostic writers: the subcommand emits
// human-readable diagnostics to stderr and the scalar/JSON result to stdout, and a
// write failure on those streams is not actionable (the process is exiting anyway).
func bfprintf(w io.Writer, format string, a ...any) { _, _ = fmt.Fprintf(w, format, a...) }
func bfprintln(w io.Writer, a ...any)               { _, _ = fmt.Fprintln(w, a...) }

// resolveBootstrapTrust builds the enforce-mode TrustStore from the SAME env inputs
// runtime startup uses (baked ∪ operator ed25519 roots + Sigstore). Bootstrap ALWAYS
// enforces: the break-glass CULVERT_RELEASE_CATALOG_VERIFY is deliberately NOT honored
// — the only fresh-install override is an explicit verified image seed. ok=false (with
// a stderr message) on any failure.
func resolveBootstrapTrust(stderr io.Writer) (trust TrustStore, keys []TrustKey, sigActive, ok bool) {
	keys, err := combinedReleaseTrustKeys(os.Getenv(envReleaseCatalogTrustKeys))
	if err != nil {
		bfprintf(stderr, "bootstrap-resolve: trust keys: %v\n", err)
		return TrustStore{}, nil, false, false
	}
	sig := resolveSigstoreWiring(os.Getenv)
	if sig.err != nil {
		bfprintf(stderr, "bootstrap-resolve: sigstore trust: %v\n", sig.err)
		return TrustStore{}, nil, false, false
	}
	if sig.warn != "" {
		bfprintf(stderr, "bootstrap-resolve: %s\n", sig.warn)
	}
	trust, err = NewTrustStoreWithSigstore(keys, VerifyEnforce, sig.verifier)
	if err != nil {
		bfprintf(stderr, "bootstrap-resolve: %v\n"+
			"  (this build carries no release-catalog trust roots; a fresh install requires a\n"+
			"   trusted verifier binary. Use an official signed build, or supply roots via %s.)\n",
			err, envReleaseCatalogTrustKeys)
		return TrustStore{}, nil, false, false
	}
	return trust, keys, sig.active, true
}

// resolveBootstrapOrigin resolves the effective catalog origin: the flag wins over
// the env, with the SAME off/none/disabled sentinel semantics runtime uses. A disabled
// origin is a HARD failure — bootstrap must never downgrade to tag enumeration; the
// installer requires an explicit seed instead. ok=false (with a stderr message) then.
func resolveBootstrapOrigin(flagVal string, stderr io.Writer) (origin, source string, ok bool) {
	catURL := strings.TrimSpace(flagVal)
	if catURL != "" {
		if isCatalogFetchDisabled(catURL) {
			bfprintf(stderr, "bootstrap-resolve: --catalog-url is a disable sentinel (%q); refusing to resolve. "+
				"Supply a real catalog origin or an explicit verified image seed.\n", catURL)
			return "", "", false
		}
		return catURL, catalogURLSourceOverride, true
	}
	catURL, source = resolveCatalogURL(os.Getenv(envReleaseCatalogURL))
	if source == catalogURLSourceDisabled || catURL == "" {
		bfprintf(stderr, "bootstrap-resolve: catalog fetch is DISABLED via %s; there is no trusted source to resolve.\n"+
			"  A fresh install cannot proceed without either a catalog origin or an explicit verified image seed (CULVERT_PROXY_SEED_REF).\n"+
			"  This never falls back to GHCR tag discovery.\n", envReleaseCatalogURL)
		return "", "", false
	}
	return catURL, source, true
}

// resolveBootstrapProxyRepo returns the repo allowlist: --proxy-repo, else the env,
// else the baked default.
func resolveBootstrapProxyRepo(flagVal string) string {
	if r := strings.TrimSpace(flagVal); r != "" {
		return r
	}
	if r := strings.TrimSpace(os.Getenv(envReleaseProxyRepo)); r != "" {
		return r
	}
	return defaultReleaseProxyRepo
}

// emitBootstrapDecision persists the full decision record (best-effort) and writes
// the requested stdout content, returning the process exit code.
func emitBootstrapDecision(decision *bootstrapDecision, printSel, outPath string, stdout, stderr io.Writer) int {
	// BEST-EFFORT record: a verified decision must not be discarded because the record
	// file could not be written (e.g. a root-owned install dir under a non-root run).
	if path := strings.TrimSpace(outPath); path != "" {
		full, _ := json.MarshalIndent(decision, "", "  ")
		if err := os.WriteFile(path, append(full, '\n'), 0o600); err != nil {
			bfprintf(stderr, "bootstrap-resolve: warning: could not write decision record to %q: %v\n", sanitizeLog(path), err)
		}
	}
	if scalar, ok := bootstrapScalar(decision, printSel); ok {
		bfprintln(stdout, scalar)
		return 0
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(decision); err != nil {
		bfprintf(stderr, "bootstrap-resolve: encode decision: %v\n", err)
		return 1
	}
	return 0
}

// validBootstrapPrint reports whether v is an accepted --print value.
func validBootstrapPrint(v string) bool {
	switch v {
	case "json", "image_ref", "digest", "version_id", "repo", "catalog_version":
		return true
	default:
		return false
	}
}

// bootstrapScalar returns the single field selected by --print (ok=false for
// "json", which the caller renders as the full object).
func bootstrapScalar(d *bootstrapDecision, which string) (string, bool) {
	switch which {
	case "image_ref":
		return d.ImageRef, true
	case "digest":
		return d.Digest, true
	case "version_id":
		return d.VersionID, true
	case "repo":
		return d.Repo, true
	case "catalog_version":
		return fmt.Sprintf("%d", d.CatalogVersion), true
	default:
		return "", false
	}
}

// bootstrapResolveOpts are the fully-resolved inputs to the resolve core. Tests
// construct this directly with a fixture TrustStore + a loopback origin, so the
// security kernel is exercised without env or network dependencies.
type bootstrapResolveOpts struct {
	catalogURL     string
	originSource   string
	trust          TrustStore
	channel        Channel
	installChannel string
	proxyRepo      string
	statePath      string // "" ⇒ zero rollback floor (fresh host)
	stageBase      string // "" ⇒ os.TempDir()
	trustSchemes   string

	// now overrides the freshness clock (tests). nil ⇒ time.Now.
	now func() time.Time
	// insecureGuard disables the provider SSRF guard for loopback test origins.
	// NEVER set in production (the CLI wrapper leaves it false).
	insecureGuard bool
}

// bootstrapResolve fetches, verifies, and resolves the catalog into an install
// decision. It is the shared security kernel: fetch (two-phase SSRF-guarded) →
// LoadVerifiedCatalog (signature) → freshness → rollback → replay → channel
// resolve → repo allowlist → digest. Any failure returns a non-nil error and NO
// decision (fail closed).
func bootstrapResolve(ctx context.Context, opts bootstrapResolveOpts) (*bootstrapDecision, error) {
	// Defense-in-depth inline SSRF preflight so CodeQL sees the guard; the provider
	// ALSO guards at dial time and on redirects (the authoritative, DNS-rebind check).
	if err := bootstrapCheckOrigin(opts.catalogURL, opts.insecureGuard); err != nil {
		return nil, err
	}

	prov, err := NewHTTPCatalogProvider(opts.catalogURL, opts.trust)
	if err != nil {
		return nil, errors.New(redactSeedError(err, opts.catalogURL))
	}
	if opts.stageBase != "" {
		prov.SetStageBase(opts.stageBase)
	}
	if opts.insecureGuard {
		prov.guard = nil // loopback tests only
	}

	stage, err := prov.Stage(ctx)
	if err != nil {
		if errors.Is(err, errCatalogUnchanged) {
			// A fresh resolve sends no validators, so a 304 means the origin is
			// misbehaving — treat as no catalog staged (fail closed).
			return nil, errors.New("catalog origin returned 304 to an unconditional request; no catalog staged")
		}
		// A transport error wraps net/http's *url.Error, whose string embeds the full
		// request URL (path + query + any userinfo) — a presigned/credentialed operator
		// mirror URL would otherwise leak into the installer's logs. Redact to host-only
		// (the SAME pattern the runtime auto-seed uses).
		return nil, fmt.Errorf("fetch/stage catalog: %s", redactSeedError(err, opts.catalogURL))
	}
	defer func() { _ = os.RemoveAll(stage) }()

	// Re-verify the staged dir end-to-end (signature + every manifest_sha256 hash
	// binding) — defense in depth on top of the provider's Phase-1 index gate.
	cat, err := LoadVerifiedCatalog(&dirCatalogSource{dir: stage}, opts.trust)
	if err != nil {
		return nil, fmt.Errorf("verify catalog: %w", err)
	}

	now := time.Now
	if opts.now != nil {
		now = opts.now
	}
	if err := checkCatalogFreshness(cat, now(), catalogClockSkew); err != nil {
		return nil, fmt.Errorf("catalog freshness: %w", err)
	}
	if err := bootstrapCheckFloor(cat, opts.statePath); err != nil {
		return nil, err
	}

	rel, repo, digest, err := bootstrapResolveDigest(cat, opts.channel, opts.proxyRepo)
	if err != nil {
		return nil, err
	}

	return &bootstrapDecision{
		SchemaVersion:  bootstrapDecisionSchema,
		InstallChannel: opts.installChannel,
		CatalogChannel: string(opts.channel),
		Repo:           repo,
		ImageRef:       repo + "@" + digest,
		Digest:         digest,
		ReleaseID:      rel.ReleaseID,
		VersionID:      rel.VersionID,
		Severity:       string(rel.Severity),
		CatalogVersion: cat.Version(),
		GeneratedAt:    cat.GeneratedAt().UTC().Format(time.RFC3339),
		ExpiresAt:      cat.ExpiresAt().UTC().Format(time.RFC3339),
		TrustSchemes:   opts.trustSchemes,
		CatalogOrigin:  seedHost(opts.catalogURL), // host only (never a credentialed URL)
	}, nil
}

// bootstrapCheckOrigin is the inline SSRF preflight: url.Parse + scheme + host +
// isPrivateHost (skipped only for loopback test origins via insecureGuard).
func bootstrapCheckOrigin(catalogURL string, insecureGuard bool) error {
	u, err := url.Parse(catalogURL)
	if err != nil {
		return fmt.Errorf("parse catalog URL: %w", err)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return fmt.Errorf("catalog URL scheme %q must be http or https", u.Scheme)
	}
	if u.Host == "" {
		return errors.New("catalog URL has no host")
	}
	if !insecureGuard {
		if err := isPrivateHost(u.Host); err != nil {
			return fmt.Errorf("catalog origin rejected (SSRF guard): %w", err)
		}
	}
	return nil
}

// bootstrapCheckFloor applies anti-rollback + replay against the appliance's
// persisted floor when a data dir was supplied. A missing floor file is the normal
// fresh-host state (zero floor). The AUTHORITATIVE ratchet still runs in the
// appliance's own enforce-mode startup; this is a best-effort bootstrap guard so a
// re-run over an existing deployment never resolves a rolled-back catalog.
func bootstrapCheckFloor(cat *Catalog, statePath string) error {
	floorVersion := 0
	var floorGen time.Time
	if statePath != "" {
		st, err := (freshnessPolicy{enabled: true, statePath: statePath}).readFloorState()
		if err != nil {
			return fmt.Errorf("read rollback floor %q: %w", sanitizeLog(statePath), err)
		}
		floorVersion = st.HighestVersion
		if floorGen, err = parseFloorGen(st.HighestGeneratedAt); err != nil {
			return fmt.Errorf("parse rollback floor: %w", err)
		}
	}
	if err := checkCatalogRollback(cat, floorVersion); err != nil {
		return fmt.Errorf("catalog rollback: %w", err)
	}
	if err := checkCatalogReplay(cat, floorVersion, floorGen); err != nil {
		return fmt.Errorf("catalog replay: %w", err)
	}
	return nil
}

// bootstrapResolveDigest resolves the channel to its release and validated
// repo/digest, enforcing the repo allowlist. The catalog binds each ref to
// repo@sha256:<64hex>; this rejects a (validly-signed) catalog pointing at an
// unexpected registry/repo.
func bootstrapResolveDigest(cat *Catalog, channel Channel, proxyRepo string) (rel Release, repo, digest string, err error) {
	rr, err := cat.Resolve(channel)
	if err != nil {
		return Release{}, "", "", err
	}
	rel, ok := cat.Lookup(rr.PinnedRef)
	if !ok {
		// Cannot happen for a well-formed catalog (Resolve returns a catalog ref),
		// but never trust an internal invariant when the result gates a pull.
		return Release{}, "", "", fmt.Errorf("resolved release %q is not present in the catalog index", rr.ReleaseID)
	}
	repo, digest, ok = strings.Cut(rr.PinnedRef, "@")
	if !ok || repo == "" || !strings.HasPrefix(digest, "sha256:") {
		return Release{}, "", "", fmt.Errorf("resolved pinned ref %q is not repo@sha256:<digest>", sanitizeLog(rr.PinnedRef))
	}
	if repo != proxyRepo {
		return Release{}, "", "", fmt.Errorf("resolved repo %q is outside the allowlist (expected %q)",
			sanitizeLog(repo), sanitizeLog(proxyRepo))
	}
	return rel, repo, digest, nil
}

// mapInstallChannel maps an operator-facing install channel to a catalog Channel.
// "stable" is the product-facing name for the catalog's "recommended" mainline.
func mapInstallChannel(s string) (Channel, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "stable", "recommended":
		return ChannelRecommended, nil
	case "lts":
		return ChannelLTS, nil
	case "critical":
		return ChannelCritical, nil
	default:
		return "", fmt.Errorf("unknown install channel %q (want stable|lts|critical)", sanitizeLog(s))
	}
}

// trustSchemesOf returns a compact, log-safe description of the active trust
// schemes for the decision output (mirrors trustSchemes(cfg) without a full cfg).
func trustSchemesOf(keys []TrustKey, sigstoreActive bool) string {
	schemes := make([]string, 0, 2)
	if len(keys) > 0 {
		schemes = append(schemes, catalogSigAlg)
	}
	if sigstoreActive {
		schemes = append(schemes, sigstoreSigAlg)
	}
	if len(schemes) == 0 {
		return "none"
	}
	return strings.Join(schemes, "+")
}
