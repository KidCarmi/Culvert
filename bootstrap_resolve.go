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
// (`culvert-linux-<arch>` + `.sigstore.json`); the installer cosign-verifies it
// against the SAME pinned identity before executing it. So the whole chain —
// verifier binary, catalog, and resolved image — is signature-gated under one
// trust policy that cannot drift from the runtime (TestReleaseIdentitySSOT +
// the contract tests in bootstrap_resolve_test.go pin this).
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
		fmt.Fprintf(stderr, "bootstrap-resolve: --print %q is not one of json|image_ref|digest|version_id|repo|catalog_version\n", *printFlag)
		return 2
	}

	// ── Trust config: the SAME inputs runtime startup uses. ────────────────────
	// Bootstrap ALWAYS enforces: the installer must never accept an unsigned or
	// stale catalog. The break-glass CULVERT_RELEASE_CATALOG_VERIFY (permissive/
	// disabled) is deliberately NOT honored here — the only supported override for
	// a fresh install is an explicit, verified image seed (CULVERT_PROXY_SEED_REF),
	// handled entirely in the installer, never a relaxed catalog trust mode.
	keys, err := combinedReleaseTrustKeys(os.Getenv(envReleaseCatalogTrustKeys))
	if err != nil {
		fmt.Fprintf(stderr, "bootstrap-resolve: trust keys: %v\n", err)
		return 1
	}
	sig := resolveSigstoreWiring(os.Getenv)
	if sig.err != nil {
		fmt.Fprintf(stderr, "bootstrap-resolve: sigstore trust: %v\n", sig.err)
		return 1
	}
	if sig.warn != "" {
		fmt.Fprintf(stderr, "bootstrap-resolve: %s\n", sig.warn)
	}
	trust, err := NewTrustStoreWithSigstore(keys, VerifyEnforce, sig.verifier)
	if err != nil {
		fmt.Fprintf(stderr, "bootstrap-resolve: %v\n"+
			"  (this build carries no release-catalog trust roots; a fresh install requires a\n"+
			"   trusted verifier binary. Use an official signed build, or supply roots via %s.)\n",
			err, envReleaseCatalogTrustKeys)
		return 1
	}

	// ── Catalog origin. The flag wins over the env; the env is parsed with the
	// SAME resolver runtime uses so the off/none/disabled sentinels mean the same
	// thing. A disabled origin is a HARD ERROR here — bootstrap must never silently
	// downgrade to tag enumeration; the installer requires an explicit seed instead.
	catURL := strings.TrimSpace(*catalogURLFlag)
	var originSource string
	if catURL != "" {
		if isCatalogFetchDisabled(catURL) {
			fmt.Fprintf(stderr, "bootstrap-resolve: --catalog-url is a disable sentinel (%q); refusing to resolve. "+
				"Supply a real catalog origin or an explicit verified image seed.\n", catURL)
			return 1
		}
		originSource = catalogURLSourceOverride
	} else {
		catURL, originSource = resolveCatalogURL(os.Getenv(envReleaseCatalogURL))
	}
	if originSource == catalogURLSourceDisabled || catURL == "" {
		fmt.Fprintf(stderr, "bootstrap-resolve: catalog fetch is DISABLED via %s; there is no trusted source to resolve.\n"+
			"  A fresh install cannot proceed without either a catalog origin or an explicit verified image seed (CULVERT_PROXY_SEED_REF).\n"+
			"  This never falls back to GHCR tag discovery.\n", envReleaseCatalogURL)
		return 1
	}

	channel, err := mapInstallChannel(*channelFlag)
	if err != nil {
		fmt.Fprintf(stderr, "bootstrap-resolve: %v\n", err)
		return 1
	}

	proxyRepo := strings.TrimSpace(*proxyRepoFlag)
	if proxyRepo == "" {
		proxyRepo = strings.TrimSpace(os.Getenv(envReleaseProxyRepo))
	}
	if proxyRepo == "" {
		proxyRepo = defaultReleaseProxyRepo
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
		proxyRepo:      proxyRepo,
		statePath:      statePath,
		stageBase:      strings.TrimSpace(*stageDirFlag),
		trustSchemes:   trustSchemesOf(keys, sig.active),
	})
	if err != nil {
		fmt.Fprintf(stderr, "bootstrap-resolve: %v\n", err)
		return 1
	}

	// Persist the full decision record first (the appliance keeps it to prove which
	// catalog decision bootstrapped it), then emit the requested stdout content.
	if path := strings.TrimSpace(*outFlag); path != "" {
		full, _ := json.MarshalIndent(decision, "", "  ")
		if err := os.WriteFile(path, append(full, '\n'), 0o600); err != nil {
			fmt.Fprintf(stderr, "bootstrap-resolve: write decision to %q: %v\n", sanitizeLog(path), err)
			return 1
		}
	}
	if scalar, ok := bootstrapScalar(decision, *printFlag); ok {
		fmt.Fprintln(stdout, scalar)
		return 0
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(decision); err != nil {
		fmt.Fprintf(stderr, "bootstrap-resolve: encode decision: %v\n", err)
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
	// Defense-in-depth inline SSRF preflight (url.Parse + scheme + isPrivateHost)
	// at the call site so CodeQL sees the guard; the provider ALSO guards at dial
	// time and on redirects (the authoritative, DNS-rebind-proof check).
	u, err := url.Parse(opts.catalogURL)
	if err != nil {
		return nil, fmt.Errorf("parse catalog URL: %w", err)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return nil, fmt.Errorf("catalog URL scheme %q must be http or https", u.Scheme)
	}
	if u.Host == "" {
		return nil, errors.New("catalog URL has no host")
	}
	if !opts.insecureGuard {
		if err := isPrivateHost(u.Host); err != nil {
			return nil, fmt.Errorf("catalog origin rejected (SSRF guard): %w", err)
		}
	}

	prov, err := NewHTTPCatalogProvider(opts.catalogURL, opts.trust)
	if err != nil {
		return nil, err
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
		return nil, fmt.Errorf("fetch/stage catalog: %w", err)
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

	// Anti-rollback + replay against the appliance's persisted floor, when a data
	// dir was supplied and it exists. A missing floor file is the normal fresh-host
	// state (zero floor). The AUTHORITATIVE floor ratchet still happens inside the
	// appliance's own enforce-mode startup; this is a best-effort bootstrap guard
	// so a re-run over an existing deployment never resolves a rolled-back catalog.
	floorVersion := 0
	var floorGen time.Time
	if opts.statePath != "" {
		st, err := (freshnessPolicy{enabled: true, statePath: opts.statePath}).readFloorState()
		if err != nil {
			return nil, fmt.Errorf("read rollback floor %q: %w", sanitizeLog(opts.statePath), err)
		}
		floorVersion = st.HighestVersion
		if floorGen, err = parseFloorGen(st.HighestGeneratedAt); err != nil {
			return nil, fmt.Errorf("parse rollback floor: %w", err)
		}
	}
	if err := checkCatalogRollback(cat, floorVersion); err != nil {
		return nil, fmt.Errorf("catalog rollback: %w", err)
	}
	if err := checkCatalogReplay(cat, floorVersion, floorGen); err != nil {
		return nil, fmt.Errorf("catalog replay: %w", err)
	}

	// Resolve the channel forward to its immutable pinned ref.
	rr, err := cat.Resolve(opts.channel)
	if err != nil {
		return nil, err
	}
	rel, ok := cat.Lookup(rr.PinnedRef)
	if !ok {
		// Cannot happen for a well-formed catalog (Resolve returns a catalog ref),
		// but never trust an internal invariant when the result gates a pull.
		return nil, fmt.Errorf("resolved release %q is not present in the catalog index", rr.ReleaseID)
	}

	// Repository allowlist: the resolved image MUST live in the expected repo. The
	// catalog already binds each ref to repo@sha256:<64hex>; this rejects a catalog
	// (even a validly-signed one) that points at an unexpected registry/repo.
	repo, digest, ok := strings.Cut(rr.PinnedRef, "@")
	if !ok || repo == "" || !strings.HasPrefix(digest, "sha256:") {
		return nil, fmt.Errorf("resolved pinned ref %q is not repo@sha256:<digest>", sanitizeLog(rr.PinnedRef))
	}
	if repo != opts.proxyRepo {
		return nil, fmt.Errorf("resolved repo %q is outside the allowlist (expected %q)",
			sanitizeLog(repo), sanitizeLog(opts.proxyRepo))
	}

	origin := ""
	if h := seedHost(opts.catalogURL); h != "" {
		origin = h
	}

	return &bootstrapDecision{
		SchemaVersion:  bootstrapDecisionSchema,
		InstallChannel: opts.installChannel,
		CatalogChannel: string(opts.channel),
		Repo:           repo,
		ImageRef:       rr.PinnedRef,
		Digest:         digest,
		ReleaseID:      rel.ReleaseID,
		VersionID:      rel.VersionID,
		Severity:       string(rel.Severity),
		CatalogVersion: cat.Version(),
		GeneratedAt:    cat.GeneratedAt().UTC().Format(time.RFC3339),
		ExpiresAt:      cat.ExpiresAt().UTC().Format(time.RFC3339),
		TrustSchemes:   opts.trustSchemes,
		CatalogOrigin:  origin,
	}, nil
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
