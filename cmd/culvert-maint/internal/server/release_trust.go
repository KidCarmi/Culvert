package server

import (
	"errors"

	"github.com/KidCarmi/Culvert/releaseproof"
)

// maxProofBodyBytes permits two four-document, base64-encoded evidence sets.
// Other API routes retain their original 16 KiB request cap.
const maxProofBodyBytes = 12 << 20

// ReleaseTrust is the host-owned signed release authorization boundary. Test
// rigs may supply a fake explicitly; missing production wiring always denies.
type ReleaseTrust interface {
	Check(string, *releaseproof.Evidence) error
	Prepare(string, *releaseproof.Evidence, string, *releaseproof.Evidence) error
	AdmitRollback(string, *releaseproof.Evidence) error
	Known(string) error
}

func (s *Server) checkRelease(ref string, p *releaseproof.Evidence) error {
	if s.opts.ReleaseTrust == nil {
		return errors.New("release trust unavailable")
	}
	return s.opts.ReleaseTrust.Check(ref, p)
}

func (s *Server) prepareRelease(ref string, p *releaseproof.Evidence, prior string, pp *releaseproof.Evidence) error {
	if s.opts.ReleaseTrust == nil {
		return errors.New("release trust unavailable")
	}
	return s.opts.ReleaseTrust.Prepare(ref, p, prior, pp)
}

func (s *Server) knownRelease(ref string) error {
	if s.opts.ReleaseTrust == nil {
		return errors.New("release trust unavailable")
	}
	return s.opts.ReleaseTrust.Known(ref)
}
