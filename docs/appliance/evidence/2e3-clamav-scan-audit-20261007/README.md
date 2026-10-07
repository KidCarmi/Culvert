# Replacement ClamAV exact-image evidence gap

**BLOCKED for an exact baked-sidecar scan/SBOM claim.** No new vulnerability is demonstrated. The remediation version, archive closure and functional scanner checks pass.

Authenticated, read-only metadata now proves the exact archive `603c165c...` contains OCI index `f3fcbf45...` → amd64 manifest `be3827e2...` → config **`098ca807...`**. The parent's receipt reports exit 0 and binds the preserved output by SHA256. The full mapping and layer descriptors are in `guest-sidecar-metadata.json`.

The successful current Deep scan applies to separately built image ID `3f6a669b...`. Its retained artifact has a table and functional checks but no config/rootfs metadata, so package/filesystem equivalence with `098ca807...` cannot be established. The older committed scan (`5fe41440...`) shares seven base layers but differs in the final derivative layer. Different config or layer hashes do not themselves prove a vulnerability; they prevent transferring a clean scan without further evidence.

See [request-to-opus.md](request-to-opus.md) for the exact offline archive scan request and [audit.json](audit.json) for all IDs, source references and limitations. Parent performed the metadata read; this reviewer made no live calls. Only this directory is the sanitized supplement. The prior supplement has been updated and its checksums regenerated.
