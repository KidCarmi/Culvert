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
)

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
	}
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
