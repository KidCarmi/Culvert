package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/fs"

	"github.com/KidCarmi/Culvert/releaseproof"
)

// The catalog already bounds individual documents. Bound retained manifests as
// a group too: forwarding evidence must not multiply an index into unbounded RAM.
const catalogProofMaxBytes = 16 << 20

type catalogProofSnapshot struct {
	index, bundle, signature []byte
	manifests                map[string][]byte // release ID -> exact manifest bytes
}

// catalogProofCapture observes the SAME reads used by signature/hash checks.
// No dispatch-time source read can substitute a newer index or manifest.
type catalogProofCapture struct {
	SignedCatalogSource
	bundle    []byte
	signature []byte
	manifests map[string][]byte // manifest reference -> bytes
	retained  int
}

func (s *catalogProofCapture) ReadSignature() ([]byte, error) {
	raw, err := s.SignedCatalogSource.ReadSignature()
	if err != nil {
		return nil, err
	}
	if len(raw) > catalogMaxReadBytes {
		return nil, errSigOversize
	}
	s.signature = bytes.Clone(raw)
	return bytes.Clone(s.signature), nil
}

func (s *catalogProofCapture) ReadSigstoreBundle() ([]byte, error) {
	src, ok := s.SignedCatalogSource.(sigstoreSource)
	if !ok {
		return nil, fs.ErrNotExist
	}
	raw, err := src.ReadSigstoreBundle()
	if err != nil {
		return nil, err
	}
	if len(raw) > catalogMaxReadBytes {
		return nil, errSigstoreOversize
	}
	s.bundle = bytes.Clone(raw)
	return bytes.Clone(s.bundle), nil
}

func (s *catalogProofCapture) ReadManifest(ref string) ([]byte, error) {
	if raw, ok := s.manifests[ref]; ok {
		return bytes.Clone(raw), nil
	}
	raw, err := s.SignedCatalogSource.ReadManifest(ref)
	if err != nil {
		return nil, err
	}
	if len(raw) > catalogMaxReadBytes || len(raw) > catalogProofMaxBytes-s.retained {
		return nil, errors.New("release catalog: retained proof exceeds size bound")
	}
	s.manifests[ref] = bytes.Clone(raw)
	s.retained += len(raw)
	return bytes.Clone(s.manifests[ref]), nil
}

func (s *catalogProofCapture) snapshot(index []byte) *catalogProofSnapshot {
	// Legacy/disabled/unsigned catalogs stay readable according to the existing
	// proxy policy, but do not invent the evidence required by the host agent.
	if len(s.bundle) == 0 && len(s.signature) == 0 {
		return nil
	}
	var idx catalogIndexFile
	if json.Unmarshal(index, &idx) != nil {
		return nil // the structural loader already rejects this path
	}
	p := &catalogProofSnapshot{index: bytes.Clone(index), bundle: bytes.Clone(s.bundle), signature: bytes.Clone(s.signature), manifests: make(map[string][]byte)}
	for _, entry := range idx.Releases {
		p.manifests[entry.ReleaseID] = s.manifests[entry.ManifestRef]
	}
	return p
}

func (c *Catalog) releaseProof(id string) *releaseproof.Evidence {
	if c == nil || c.proof == nil {
		return nil
	}
	manifest, ok := c.proof.manifests[id]
	if !ok {
		return nil
	}
	return &releaseproof.Evidence{ReleaseID: id, Index: bytes.Clone(c.proof.index),
		SigstoreBundle: bytes.Clone(c.proof.bundle), Signature: bytes.Clone(c.proof.signature), Manifest: bytes.Clone(manifest)}
}
