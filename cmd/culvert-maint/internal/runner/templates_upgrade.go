// D1.6c runner templates: the read-only image-inspection commands that
// back POST /v1/upgrades/check.
//
// CONTRACT (non-negotiable, mirrors D1.6 plan § 4.1, § 4.6):
//
//   - One template = one method on *Runner with explicit, typed args.
//     The method validates inputs, builds argv in the canonical order,
//     and calls runWithEnv. There is no generic dispatch.
//   - The only variable argv position is <image_ref>. It is bounded
//     twice: the handler enforces the operator's image_allowlist regex
//     (policy), and the runner enforces validateImageRefShape (argv
//     safety — no whitespace, no shell metacharacters, no leading dash
//     that docker could read as a flag). The sudoers entry ends in a
//     sole trailing `*` for that one token, the only argument wildcard
//     sudo-rs accepts.
//   - The upgrade-apply templates (container inspect, pinned pull,
//     retag) carry per-call values sudoers cannot match without a glob,
//     so in sudo mode they run through the compose-cli wrapper
//     (WrapperArgv), like the backup/restore templates.
//   - Both commands are READ-ONLY: `docker image inspect` reads the
//     local image store; `docker manifest inspect` queries the registry.
//     Neither mutates the host, the stack, or /data. They never acquire
//     the maintenance lock.
//   - No backup passphrase is forwarded; the inspect calls suppress
//     CULVERT_BACKUP_PASSPHRASE in the child env so a host-side value
//     can't leak into a docker subprocess that has no use for it.
//
// Sudoers is the privilege boundary; the agent's validation is
// defense-in-depth. The parity test asserts the bidirectional match
// between these templates' SudoersLines and packaging/sudoers/culvert-maint.
package runner

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

const (
	// TemplateComposeImageInspect runs `docker image inspect <image_ref>`
	// and emits the local image record (JSON array) on stdout. Read-only;
	// used by /v1/upgrades/check to learn the locally-present digest.
	TemplateComposeImageInspect TemplateID = "compose.image.inspect"
	// TemplateComposeManifestInspect runs
	// `docker manifest inspect --verbose <image_ref>` and emits the
	// remote manifest descriptor(s) on stdout. Read-only; used by
	// /v1/upgrades/check to learn the registry-side digest for the
	// requested image_ref.
	TemplateComposeManifestInspect TemplateID = "compose.manifest.inspect"
	// TemplateComposeContainerInspect runs
	// `docker inspect --format '{{json .Image}}' <container_id>` and
	// emits the running container's image config digest (`sha256:…`) on
	// stdout. Read-only; used by the upgrade-apply capture step to learn
	// which image the running proxy container is actually executing —
	// NOT what a tag currently resolves to in the local cache (#351).
	// The endpoint that consumes it (/v1/upgrades/apply) is NOT activated
	// by this slice; only the read-only primitive lands.
	TemplateComposeContainerInspect TemplateID = "compose.container.inspect"
	// TemplateImagePullDigest runs `docker pull <proxy_repo>@sha256:<digest>`
	// — a RAW docker pull of a repo-bound, digest-pinned reference (P1.4).
	// State-changing (mutates the local image store). In sudo mode it runs
	// as the compose-cli wrapper's `pull` subcommand: the repo is a literal
	// rendered into the root-owned wrapper and the digest must be exactly 64
	// lowercase hex, so the privilege boundary itself bounds what may be
	// pulled.
	TemplateImagePullDigest TemplateID = "image.pull.digest"
	// TemplateImageTagPinned runs
	// `docker tag <proxy_repo>@sha256:<digest> culvert/proxy:pinned` —
	// retagging the just-pulled digest to the FIXED local tag the compose
	// file resolves. Source is repo+digest bound; the destination is the
	// fixed literal `culvert/proxy:pinned` (P1.4). State-changing.
	TemplateImageTagPinned TemplateID = "image.tag.pinned"
)

// pinnedProxyTag is the FIXED local image tag the compose file resolves for
// the proxy (and same-image cli) service. It has no registry host and is
// never pushed — it exists only as a local alias created by ComposeTagPinned
// (or seeded at install). Nothing a caller supplies can change what
// `docker compose up` resolves it to; the only writer is the repo-bound,
// digest-validated `docker tag` command (the compose-cli wrapper's `tag`). This replaces the old
// `${CULVERT_PROXY_IMAGE:-…}` interpolation as the image-selection mechanism
// (P1.4 / D1.6c-pin-value-binding-plan.md).
const pinnedProxyTag = "culvert/proxy:pinned"

// defaultProxyRepo is the repository the pinned-digest pull/tag are bound to
// when Options.ProxyRepo is unset. It mirrors the config `proxy_repo` default
// and the canonical `image_allowlist` repo. The two MUST describe the same
// repository (see the plan's §3.1 config invariant).
const defaultProxyRepo = "ghcr.io/kidcarmi/culvert"

// pinnedDigestHexLen is the exact length of a sha256 hex digest (and the
// digest length the compose-cli wrapper's pull/tag subcommands require).
const pinnedDigestHexLen = 64

// pinnedDigestSuffixRE matches the `@sha256:<64 lowercase hex>` suffix of a
// repo-bound pinned reference. The repo prefix is checked separately against
// the runner's configured proxyRepo (a literal compare, not a regex, so a
// repo containing `.`/`/` needs no escaping).
var pinnedDigestSuffixRE = regexp.MustCompile(fmt.Sprintf(`^@sha256:[0-9a-f]{%d}$`, pinnedDigestHexLen))

// imageRefShapeRE bounds the argv shape of an image reference,
// INDEPENDENT of the operator-configured image_allowlist. It is the
// belt-and-braces barrier: even if an operator writes a sloppy
// image_allowlist regex, the runner refuses to forward a token that
// contains whitespace, control characters, or shell metacharacters, or
// that begins with a character `docker` could parse as a flag.
//
// The reference must start with an alphanumeric (so no leading '-' or
// '.'), then allow only the characters that appear in legitimate
// registry references: letters, digits, and the separators `._-/:@`.
// Length is bounded to 512 bytes total.
var imageRefShapeRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/:@-]{0,511}$`)

// ValidateImageRef is the exported argv-safety validator for an image
// reference. It checks the bounded shape ONLY — the policy gate
// (membership in the operator's image_allowlist) is enforced by the
// handler before this is reached. Exported so handlers can fail fast
// with a clean 400 before any runner method is invoked.
func ValidateImageRef(ref string) error { return validateImageRefShape(ref) }

// validateImageRefShape is the unexported implementation. Returns an
// error if ref is empty, over-long, begins with a flag-like character,
// or contains any byte outside the bounded registry-reference charset.
func validateImageRefShape(ref string) error {
	if ref == "" {
		return errors.New("image_ref: empty")
	}
	if len(ref) > 512 {
		return fmt.Errorf("image_ref: must be at most 512 bytes, got %d", len(ref))
	}
	if !imageRefShapeRE.MatchString(ref) {
		return fmt.Errorf("image_ref: must start with an alphanumeric and contain only [A-Za-z0-9._/:@-] with no whitespace, control chars, or shell metacharacters; got %q", ref)
	}
	return nil
}

// containerIDMinLen / containerIDMaxLen bound a docker container id: a
// short id (12 hex) through a full id (64 hex). `docker compose ps
// --format json` reports the 12-character short id. The compose-cli
// wrapper's inspect-image subcommand enforces the same 12..64 bound at the
// sudo boundary (pinned by wrapper_test.go).
const (
	containerIDMinLen = 12
	containerIDMaxLen = 64
)

// containerIDShapeRE bounds the argv shape of a docker container id: a
// run of 12–64 lowercase hex characters (short id through full id).
// This is the ONLY variable argv position of the container-inspect
// template, so the bound is deliberately tight — a container id can
// never contain a separator, a dash, whitespace, or a flag-like leading
// character. The id is sourced from `docker compose ps` output (not an
// operator request), but it is validated all the same: the runner never
// forwards an unvalidated token to sudo/docker.
var containerIDShapeRE = regexp.MustCompile(fmt.Sprintf(`^[a-f0-9]{%d,%d}$`, containerIDMinLen, containerIDMaxLen))

// ValidateContainerID is the exported argv-safety validator for a docker
// container id. Exported for symmetry with ValidateImageRef so a future
// handler can fail fast before invoking the runner.
func ValidateContainerID(id string) error { return validateContainerIDShape(id) }

// validateContainerIDShape returns an error unless id is 12–64 lowercase
// hex characters.
func validateContainerIDShape(id string) error {
	if id == "" {
		return errors.New("container_id: empty")
	}
	if !containerIDShapeRE.MatchString(id) {
		return fmt.Errorf("container_id: must be 12–64 lowercase hex characters (docker container id), got %q", id)
	}
	return nil
}

// d16cTemplates returns the closed list of D1.6c templates. Appended to
// Registry() after the D1.6b set.
//
// Sudoers strings are documentation-of-record; the parity test
// cross-checks them against the on-disk sudoers file. The image and
// manifest inspect lines end in a sole trailing `*` (the one argument
// wildcard sudo-rs accepts) for the image_ref, which the agent validates
// against image_allowlist (policy) and validateImageRefShape (argv safety)
// before sudo is ever invoked. The container inspect runs through the
// compose-cli wrapper instead.
func imageInspectTemplates() []Template {
	return []Template{
		{
			ID:       TemplateComposeImageInspect,
			BaseArgv: []string{"docker", "image", "inspect"},
			SudoersLines: []string{
				"/usr/bin/docker image inspect *",
			},
			StateChanging: false,
		},
		{
			ID:       TemplateComposeManifestInspect,
			BaseArgv: []string{"docker", "manifest", "inspect", "--verbose"},
			SudoersLines: []string{
				"/usr/bin/docker manifest inspect --verbose *",
			},
			StateChanging: false,
		},
		{
			// `docker inspect` is a DIFFERENT binary surface from
			// `docker compose`. It used to be allowlisted as 53 enumerated
			// `[0-9a-f]` patterns (one per id length) with a
			// backslash-escaped space in `{{json\ .Image}}`; sudo-rs
			// compares arguments literally, so none of them ever matched.
			// In sudo mode it now runs as the compose-cli wrapper's
			// `inspect-image` subcommand, which admits exactly one
			// 12..64 lowercase-hex id and execs this BaseArgv + the id:
			// nothing can follow the id (a second `--format
			// {{json .Config.Env}}` would dump container secrets as root),
			// and `--format` stays locked to `{{json .Image}}`.
			ID:            TemplateComposeContainerInspect,
			BaseArgv:      []string{"docker", "inspect", "--format", "{{json .Image}}"},
			WrapperArgv:   []string{"inspect-image"},
			SudoersLines:  []string{composeCLIWrapperSudoersLine},
			StateChanging: false,
		},
	}
}

// composeApplyTemplates returns the D1.6c upgrade-apply image-selection
// templates (P1.4). Both are RAW docker (not `docker compose`): a digest
// pull and a retag to the fixed local tag. In sudo mode both run through
// the compose-cli wrapper (`pull`, `tag`), which binds the image to
// "<proxy_repo> @ exactly 64 lowercase hex" (proxy_repo is a literal
// rendered into the root-owned wrapper at install) and the retag
// destination to the fixed `culvert/proxy:pinned`. They used to be direct
// sudoers rules with a 64-class `[0-9a-f]` digest pattern, which sudo-rs
// matches literally and therefore never matched.
func composeApplyTemplates() []Template {
	return []Template{
		{
			ID:            TemplateImagePullDigest,
			BaseArgv:      []string{"docker", "pull"},
			WrapperArgv:   []string{"pull"},
			SudoersLines:  []string{composeCLIWrapperSudoersLine},
			StateChanging: true,
		},
		{
			ID:            TemplateImageTagPinned,
			BaseArgv:      []string{"docker", "tag"},
			WrapperArgv:   []string{"tag"},
			SudoersLines:  []string{composeCLIWrapperSudoersLine},
			StateChanging: true,
		},
	}
}

// validatePinnedDigestRef enforces that ref is a repo-bound, exact-digest
// reference: `<proxyRepo>@sha256:<64 lowercase hex>`. This is the runner-side
// mirror of the compose-cli wrapper's pull/tag check (defense-in-depth) AND
// the §3.1
// repo-consistency gate: a ref whose repo differs from the configured
// proxyRepo, or whose digest is not exactly 64 hex, is rejected before any
// argv is built — so a foreign-repo or tag pin can never reach docker.
func validatePinnedDigestRef(ref, proxyRepo string) error {
	if err := validateImageRefShape(ref); err != nil { // argv-safety belt first
		return err
	}
	prefix := proxyRepo + "@"
	if !strings.HasPrefix(ref, prefix) {
		return fmt.Errorf("pinned ref %q must be repo-bound to %q (got a different or missing repo)", ref, proxyRepo)
	}
	if !pinnedDigestSuffixRE.MatchString(ref[len(proxyRepo):]) {
		return fmt.Errorf("pinned ref %q must end with @sha256:<64 lowercase hex> (a tag is not a valid pin)", ref)
	}
	return nil
}

// ValidatePinnedDigestRef is the exported form of validatePinnedDigestRef so
// callers outside the runner — the PR-E reconcile re-validation (design §0 P0-E)
// — can re-apply the EXACT repo-bound exact-digest gate to a ref sourced from an
// (unauthenticated) journal record before feeding it to a root docker action.
// Sharing the one implementation keeps the reconcile trust gate anti-drift with
// the compose-cli wrapper's pull/tag check.
func ValidatePinnedDigestRef(ref, proxyRepo string) error {
	return validatePinnedDigestRef(ref, proxyRepo)
}

// ComposePullDigest runs `docker pull <proxy_repo>@sha256:<digest>`. The ref
// is validated as a repo-bound exact-digest pin (validatePinnedDigestRef)
// before any argv is built. State-changing; no env overlay — the image is
// selected by the argv the sudo boundary (the compose-cli wrapper) validates,
// not by an env var.
func (r *Runner) ComposePullDigest(ctx context.Context, ref string) (*Result, error) {
	if err := validatePinnedDigestRef(ref, r.proxyRepo); err != nil {
		return nil, err
	}
	tmpl := templateByID(TemplateImagePullDigest)
	if tmpl == nil {
		return nil, errors.New("runner: TemplateImagePullDigest not registered")
	}
	argv := append(r.buildArgv(tmpl), ref)
	return r.runWithEnv(ctx, argv, nil)
}

// ComposeTagPinned runs
// `docker tag <proxy_repo>@sha256:<digest> culvert/proxy:pinned`, retagging
// the just-pulled digest to the FIXED local tag the compose file resolves.
// The source ref is repo+digest validated; the destination is the fixed
// literal pinnedProxyTag (never operator-supplied). State-changing; no env
// overlay.
func (r *Runner) ComposeTagPinned(ctx context.Context, ref string) (*Result, error) {
	if err := validatePinnedDigestRef(ref, r.proxyRepo); err != nil {
		return nil, err
	}
	tmpl := templateByID(TemplateImageTagPinned)
	if tmpl == nil {
		return nil, errors.New("runner: TemplateImageTagPinned not registered")
	}
	argv := append(r.buildArgv(tmpl), ref, pinnedProxyTag)
	return r.runWithEnv(ctx, argv, nil)
}

// ComposeContainerInspect runs
// `docker inspect --format '{{json .Image}}' <container_id>`. Read-only;
// emits the running container's image config digest (`sha256:…`) on
// stdout as a JSON-quoted string. CULVERT_BACKUP_PASSPHRASE is
// explicitly suppressed — the inspect subprocess has no use for it.
//
// The container_id is validated by validateContainerIDShape before any
// argv is built, so sudo is never invoked with a malformed token. The
// sudo boundary is independent: the compose-cli wrapper's inspect-image
// subcommand admits exactly one 12..64 lowercase-hex id, so even a direct
// sudo call from a compromised agent cannot append extra arguments.
func (r *Runner) ComposeContainerInspect(ctx context.Context, containerID string) (*Result, error) {
	if err := validateContainerIDShape(containerID); err != nil {
		return nil, err
	}
	tmpl := templateByID(TemplateComposeContainerInspect)
	if tmpl == nil {
		return nil, errors.New("runner: TemplateComposeContainerInspect not registered")
	}
	argv := r.buildArgv(tmpl)
	argv = append(argv, containerID)
	overlay := map[string]string{EnvCulvertBackupPassphrase: ""} // explicit unset
	return r.runWithEnv(ctx, argv, overlay)
}

// ComposeImageInspect runs `docker image inspect <image_ref>`. Read-only.
// The CULVERT_BACKUP_PASSPHRASE env var is explicitly suppressed — the
// inspect subprocess has no use for it and a host-side value must not
// leak into it.
//
// A non-zero exit (e.g. the image is not present locally) is a normal
// outcome of an upgrade check, not a runner misconfiguration. The method
// returns the *Result (carrying the captured stdout/stderr) alongside
// the error so the caller can distinguish "absent locally" from a
// genuine failure.
func (r *Runner) ComposeImageInspect(ctx context.Context, imageRef string) (*Result, error) {
	if err := validateImageRefShape(imageRef); err != nil {
		return nil, err
	}
	tmpl := templateByID(TemplateComposeImageInspect)
	if tmpl == nil {
		return nil, errors.New("runner: TemplateComposeImageInspect not registered")
	}
	argv := r.buildArgv(tmpl)
	argv = append(argv, imageRef)
	overlay := map[string]string{EnvCulvertBackupPassphrase: ""} // explicit unset
	return r.runWithEnv(ctx, argv, overlay)
}

// ComposeManifestInspect runs
// `docker manifest inspect --verbose <image_ref>`. Read-only; queries
// the registry for the manifest descriptor(s). CULVERT_BACKUP_PASSPHRASE
// is explicitly suppressed.
func (r *Runner) ComposeManifestInspect(ctx context.Context, imageRef string) (*Result, error) {
	if err := validateImageRefShape(imageRef); err != nil {
		return nil, err
	}
	tmpl := templateByID(TemplateComposeManifestInspect)
	if tmpl == nil {
		return nil, errors.New("runner: TemplateComposeManifestInspect not registered")
	}
	argv := r.buildArgv(tmpl)
	argv = append(argv, imageRef)
	overlay := map[string]string{EnvCulvertBackupPassphrase: ""} // explicit unset
	return r.runWithEnv(ctx, argv, overlay)
}
