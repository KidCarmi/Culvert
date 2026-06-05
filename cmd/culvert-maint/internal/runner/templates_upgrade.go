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
//     that docker could read as a flag). The sudoers entry uses a single
//     bounded `*` wildcard for that one token, the same precedent as
//     /backup/* for the backup/restore templates.
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
	// TemplateComposePull runs `docker compose -f <p> pull proxy`,
	// forwarding the pinned image reference via the CULVERT_PROXY_IMAGE
	// overlay. State-changing (mutates the local image store). Used by
	// POST /v1/upgrades/apply. `proxy` is a fixed service literal, not an
	// operator argument, so the sudoers line needs no wildcard there.
	TemplateComposePull TemplateID = "compose.pull"
)

// EnvCulvertProxyImage is the env-var name that overrides the proxy (and
// the same-image cli) service's image in docker-compose.yml:
//
//	image: ${CULVERT_PROXY_IMAGE:-ghcr.io/kidcarmi/culvert:latest}
//
// The upgrade-apply flow forwards the pinned image reference
// (`repo@sha256:…` or a tag) into `docker compose pull` / `up` via the
// CULVERT_PROXY_IMAGE overlay (ComposePull / ComposeUpWithImage), so a pin
// survives without editing the compose file. It is NOT a secret.
//
// It is registered as an OVERLAY-ONLY env var (Options.EnvOverlayOnly), so
// it can ONLY enter a child process through an explicit per-call overlay —
// never from the agent's ambient process environment. That stops an
// operator-set value from leaking onto unrelated compose calls (e.g. a
// restore's `up -d`); the apply pull/up overlay is the sole entry point.
//
// Under privilege_mode=sudoers the override must ALSO survive `sudo`'s
// env_reset. The install ships a matching `Defaults:culvert-maint env_keep
// += "CULVERT_PROXY_IMAGE"` line (see packaging/sudoers/culvert-maint and
// D1.6c plan § 2.3.1); without it the overlay would be stripped before
// `docker compose` saw it.
const EnvCulvertProxyImage = "CULVERT_PROXY_IMAGE"

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
// short id (12 hex) through a full id (64 hex). These are the SINGLE
// SOURCE OF TRUTH for both the argv-shape validator and the enumerated
// sudoers allowlist (containerInspectSudoersLines), so the two can never
// drift.
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
// cross-checks them against the on-disk sudoers file. The single `*`
// wildcard in each line matches exactly one argv token — the
// image_ref — which the agent validates against image_allowlist (policy)
// and validateImageRefShape (argv safety) before sudo is ever invoked.
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
			// `docker compose`. Its sudoers entries are ENUMERATED, not
			// wildcarded: one fixed-length [0-9a-f] pattern per legal
			// container-id length (12–64). There is NO trailing `*`, so
			// sudo (whose `*` matches whitespace — and could otherwise
			// admit a second `--format` to dump arbitrary Config.Env at
			// root) cannot accept any extra argument after the validated
			// id, and the `--format` value stays locked to
			// `{{json .Image}}`. This mirrors the file's restore-flag
			// enumeration: the privilege boundary is never broadened for
			// readability. The `--format` value is double-quoted because
			// `{{json .Image}}` is ONE argv token containing a space.
			ID:            TemplateComposeContainerInspect,
			BaseArgv:      []string{"docker", "inspect", "--format", "{{json .Image}}"},
			SudoersLines:  containerInspectSudoersLines(),
			StateChanging: false,
		},
	}
}

// containerInspectSudoersLines enumerates one sudoers allowlist line per
// legal container-id length (containerIDMinLen..containerIDMaxLen), each
// a fixed-length run of [0-9a-f] character classes with NO trailing
// wildcard. This bounds the privilege boundary to exactly one hex id of
// an allowed length and nothing more — see the template comment for why
// a single trailing `*` is unsafe here. The set MUST stay in lock-step
// with packaging/sudoers/culvert-maint (the parity test enforces it).
func containerInspectSudoersLines() []string {
	const prefix = `/usr/bin/docker inspect --format "{{json .Image}}" `
	lines := make([]string, 0, containerIDMaxLen-containerIDMinLen+1)
	for n := containerIDMinLen; n <= containerIDMaxLen; n++ {
		lines = append(lines, prefix+strings.Repeat("[0-9a-f]", n))
	}
	return lines
}

// composeApplyTemplates returns the D1.6c upgrade-apply templates. The
// pull is service-scoped (`proxy` is a fixed literal, no wildcard) and
// path-bound to the compose file. The matching env-preservation
// (env_keep) for CULVERT_PROXY_IMAGE lives in the sudoers Defaults block.
func composeApplyTemplates() []Template {
	return []Template{
		{
			ID:            TemplateComposePull,
			BaseArgv:      []string{"docker", "compose", "-f", "{compose_path}", "pull", "proxy"},
			SudoersLines:  []string{"/usr/bin/docker compose -f {compose_path} pull proxy"},
			StateChanging: true,
		},
	}
}

// ComposePull runs `docker compose -f <p> pull proxy`, pinning the image
// via the CULVERT_PROXY_IMAGE overlay (the compose file resolves
// `image: ${CULVERT_PROXY_IMAGE:-…}`). State-changing. The imageRef is
// validated for argv-safety (defense-in-depth; the handler already
// enforced image_allowlist).
func (r *Runner) ComposePull(ctx context.Context, imageRef string) (*Result, error) {
	if err := validateImageRefShape(imageRef); err != nil {
		return nil, err
	}
	tmpl := templateByID(TemplateComposePull)
	if tmpl == nil {
		return nil, errors.New("runner: TemplateComposePull not registered")
	}
	overlay := map[string]string{EnvCulvertProxyImage: imageRef}
	return r.runWithEnv(ctx, r.buildArgv(tmpl), overlay)
}

// ComposeUpWithImage runs `docker compose -f <p> up -d` with the
// CULVERT_PROXY_IMAGE overlay so the recreated proxy uses the pinned
// image. State-changing. Distinct from ComposeUp (which passes no
// overlay and is used by restore) so the override is explicit and never
// rides along on an unrelated up.
func (r *Runner) ComposeUpWithImage(ctx context.Context, imageRef string) (*Result, error) {
	if err := validateImageRefShape(imageRef); err != nil {
		return nil, err
	}
	tmpl := templateByID(TemplateComposeUp)
	if tmpl == nil {
		return nil, errors.New("runner: TemplateComposeUp not registered")
	}
	overlay := map[string]string{EnvCulvertProxyImage: imageRef}
	return r.runWithEnv(ctx, r.buildArgv(tmpl), overlay)
}

// ComposeContainerInspect runs
// `docker inspect --format '{{json .Image}}' <container_id>`. Read-only;
// emits the running container's image config digest (`sha256:…`) on
// stdout as a JSON-quoted string. CULVERT_BACKUP_PASSPHRASE is
// explicitly suppressed — the inspect subprocess has no use for it.
//
// The container_id is validated by validateContainerIDShape before any
// argv is built, so sudo is never invoked with a malformed token. The
// sudoers boundary is independently tightened: it enumerates a
// fixed-length hex pattern per legal id length with no trailing
// wildcard (containerInspectSudoersLines), so even a direct sudo call
// from a compromised agent cannot append extra arguments.
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
