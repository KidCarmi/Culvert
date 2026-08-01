package secret

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ── File-based local KEK (model B) ─────────────────────────────────────────

// fileProvider loads a 32-byte random KEK from a local file, generating the
// file (0600) on first use if it is absent. The KEK is stable across loads.
//
// NOTE (CA-3 ADR §9): the KEK file MUST be excluded from any backup/snapshot
// that also contains the encrypted key files, otherwise model B provides no
// protection against backup/snapshot exposure.
type fileProvider struct {
	path string
}

var _ kekSource = (*fileProvider)(nil)

func (p *fileProvider) name() string { return "file" }

// kek returns the KEK bytes, generating and persisting a fresh random KEK on
// first use if the file does not exist. An existing-but-unreadable, wrong-sized,
// or too-permissive file fails closed rather than silently regenerating (which
// would destroy the ability to decrypt previously-written material).
func (p *fileProvider) kek() ([]byte, error) {
	if _, err := os.Stat(p.path); errors.Is(err, os.ErrNotExist) {
		return p.generate()
	}
	return p.load()
}

// load reads and validates an existing KEK file: it must be exactly KEKLen bytes
// and must NOT be group/other-accessible (model B requires 0600 at rest). A
// too-permissive file is rejected rather than chmod-fixed, because a
// world-readable wrapping key may already have been exposed — failing closed
// forces operator awareness instead of silently masking the exposure.
func (p *fileProvider) load() ([]byte, error) {
	fi, err := os.Stat(p.path)
	if err != nil {
		return nil, fmt.Errorf("secret: stat key file: %w", err)
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		return nil, fmt.Errorf("secret: file %q has permissions %#o; require 0600 (no group/other access) — run: chmod 600 %q", p.path, perm, p.path)
	}
	data, err := os.ReadFile(filepath.Clean(p.path)) // filepath.Clean guards path-traversal (G304)
	if err != nil {
		return nil, fmt.Errorf("secret: read key file: %w", err)
	}
	if len(data) != KEKLen {
		// Fail closed: a malformed KEK file is not silently replaced, since doing
		// so would orphan any data already encrypted under the real KEK.
		return nil, fmt.Errorf("secret: file %q has unexpected size %d (want %d)", p.path, len(data), KEKLen)
	}
	out := make([]byte, KEKLen)
	copy(out, data)
	return out, nil
}

// generate creates a fresh random KEK and persists it 0600.
//
// It deliberately does NOT use fileutil.AtomicWrite: that helper renames over
// the destination unconditionally, so two callers racing on first use (two
// goroutines, or two processes sharing the data dir) could each generate a
// different KEK and the later rename would orphan the earlier caller's
// now-unpersisted key. Instead we write a fully-fsynced temp file and publish it
// with os.Link, which fails with EEXIST if the target already exists. The target
// therefore only ever appears as a complete file, and a caller that loses the
// race re-reads the winner's persisted KEK rather than returning its own
// orphaned bytes.
func (p *fileProvider) generate() ([]byte, error) {
	kek := make([]byte, KEKLen)
	if _, err := rand.Read(kek); err != nil {
		return nil, fmt.Errorf("secret: generate: %w", err)
	}
	dir := filepath.Dir(p.path)
	tmp, err := os.CreateTemp(dir, filepath.Base(p.path)+".tmp.*")
	if err != nil {
		return nil, fmt.Errorf("secret: create temp: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }() // best-effort: removes the temp link, leaves the published target

	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return nil, fmt.Errorf("secret: chmod temp: %w", err)
	}
	if _, err := tmp.Write(kek); err != nil {
		_ = tmp.Close()
		return nil, fmt.Errorf("secret: write temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return nil, fmt.Errorf("secret: fsync temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return nil, fmt.Errorf("secret: close temp: %w", err)
	}

	if err := os.Link(tmpName, p.path); err != nil {
		if errors.Is(err, os.ErrExist) {
			// Lost the race (or the file appeared concurrently) — load the
			// winner's complete, persisted KEK.
			return p.load()
		}
		return nil, fmt.Errorf("secret: publish key file: %w", err)
	}
	return kek, nil
}

// ── Environment / secret-supplied KEK (model C) ────────────────────────────

// envProvider sources the KEK from an environment variable holding a
// hex-encoded 32-byte key. It is the container/automation-friendly option: the
// KEK never sits on the data disk.
type envProvider struct {
	envName string
}

var _ kekSource = (*envProvider)(nil)

func (p *envProvider) name() string { return "env" }

// kek decodes the hex KEK from the configured environment variable. A missing
// variable fails closed with ErrKEKMissing; a malformed or wrong-length value
// fails closed with a descriptive (key-free) error.
func (p *envProvider) kek() ([]byte, error) {
	raw, ok := os.LookupEnv(p.envName)
	if !ok || raw == "" {
		return nil, ErrKEKMissing
	}
	k, err := hex.DecodeString(strings.TrimSpace(raw))
	if err != nil {
		return nil, fmt.Errorf("secret: env %s is not valid hex", p.envName)
	}
	if len(k) != KEKLen {
		return nil, fmt.Errorf("secret: env %s decodes to %d bytes (want %d)", p.envName, len(k), KEKLen)
	}
	return k, nil
}

// ── In-memory KEK (test / dormant-package support) ─────────────────────────

// memProvider holds a KEK entirely in memory. It backs MemoryProvider, the
// deterministic KEK source used by the dormant credential-broker package
// (internal/mcp/credentials) for its encrypted cache in tests, benchmarks and
// fuzzing, where a process-global env var (model C) or an on-disk file (model B)
// would be racy or unavailable. It holds the KEK at the same trust level as the
// file/env sources (the raw bytes never cross the Provider boundary) and never
// formats them.
type memProvider struct {
	k []byte
}

var _ kekSource = (*memProvider)(nil)

func (p *memProvider) name() string { return "memory" }

func (p *memProvider) kek() ([]byte, error) {
	if len(p.k) != KEKLen {
		return nil, ErrKEKMissing
	}
	out := make([]byte, KEKLen)
	copy(out, p.k)
	return out, nil
}

// MemoryProvider returns an opaque Provider backed by an in-memory KEK. It COPIES
// key so the caller's slice is not retained. key must be exactly KEKLen bytes; an
// out-of-size key yields a provider that fails closed (ErrKEKMissing) on use. This
// is the smallest in-memory KEK source for exercising the encrypted-cache path of
// the dormant credential broker deterministically; production consumers still use
// FileProvider/EnvProvider/ResolveProvider.
func MemoryProvider(key []byte) *Provider {
	k := make([]byte, len(key))
	copy(k, key)
	return &Provider{src: &memProvider{k: k}}
}

// ── Constructors / resolution ──────────────────────────────────────────────

// FileProvider returns an opaque Provider backed by the KEK file at path
// (model B), auto-generated 0600 on first use.
func FileProvider(path string) *Provider {
	return &Provider{src: &fileProvider{path: filepath.Clean(path)}}
}

// EnvProvider returns an opaque Provider reading a hex KEK from the given env
// var (model C). An empty name defaults to EnvKEKName.
func EnvProvider(envName string) *Provider {
	if envName == "" {
		envName = EnvKEKName
	}
	return &Provider{src: &envProvider{envName: envName}}
}

// ResolveProvider selects a provider deterministically: if the env var (envName,
// default CULVERT_KEK) is set and non-empty, the env provider (model C) is used;
// otherwise the file provider (model B) backed by filePath is used, which
// auto-generates the KEK file on first use. It performs no I/O itself; the
// returned provider reads its source lazily on the first KEK use.
func ResolveProvider(envName, filePath string) *Provider {
	if envName == "" {
		envName = EnvKEKName
	}
	if v, ok := os.LookupEnv(envName); ok && v != "" {
		return EnvProvider(envName)
	}
	return FileProvider(filePath)
}
