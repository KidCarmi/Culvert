// Package ldapstub is a MINIMAL in-process LDAP v3 responder for tests and
// the browser smoke harness (FE-6A.2 correction, Blocker 3): the appliance's
// enabled-LDAP writes now cross the connection preflight at the write
// boundary unconditionally, so every journey that ENABLES an LDAP profile
// needs a directory that actually answers. It speaks exactly what the
// preflight exercises — BindRequest → BindResponse (success, or
// invalidCredentials when configured to refuse), a base-object
// SearchRequest → one SearchResultEntry naming the requested base + a
// SearchResultDone (success, or noSuchObject for an unknown base), and
// UnbindRequest → close. Everything else is answered with an
// unwillingToPerform result. No TLS, no StartTLS, no authorization: it is a
// deterministic fixture, never a directory.
package ldapstub

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"

	ber "github.com/go-asn1-ber/asn1-ber"
)

// LDAP application tags (RFC 4511 §4).
const (
	appBindRequest       = 0
	appBindResponse      = 1
	appUnbindRequest     = 2
	appSearchRequest     = 3
	appSearchResultEntry = 4
	appSearchResultDone  = 5
	appExtendedRequest   = 23
	appExtendedResponse  = 24
)

// LDAP result codes (RFC 4511 §4.1.9).
const (
	resultSuccess            = 0
	resultNoSuchObject       = 32
	resultInvalidCredentials = 49
	resultUnwillingToPerform = 53
	resultProtocolError      = 2
)

// Options shape the stub's verdicts.
type Options struct {
	// RejectBind answers every non-anonymous bind with invalidCredentials.
	RejectBind bool
	// KnownBases restricts base-object searches; empty = every base exists.
	KnownBases []string
	// BindDN/BindPassword, when both set, are the only accepted simple bind.
	BindDN       string
	BindPassword string
}

// Server is one listening stub.
type Server struct {
	ln    net.Listener
	opts  Options
	wg    sync.WaitGroup
	binds atomic.Int64
	conns atomic.Int64
	done  chan struct{}
}

// Listen starts a stub on addr ("127.0.0.1:0" for an ephemeral port).
func Listen(addr string, opts Options) (*Server, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	s := &Server{ln: ln, opts: opts, done: make(chan struct{})}
	s.wg.Add(1)
	go s.serve()
	return s, nil
}

// Addr is the listening address (host:port).
func (s *Server) Addr() string { return s.ln.Addr().String() }

// URL is the ldap:// URL clients dial.
func (s *Server) URL() string { return "ldap://" + s.Addr() }

// Binds counts the bind requests received (a preflight that ran).
func (s *Server) Binds() int64 { return s.binds.Load() }

// Conns counts accepted connections.
func (s *Server) Conns() int64 { return s.conns.Load() }

// Close stops the listener and waits for the accept loop.
func (s *Server) Close() {
	select {
	case <-s.done:
		return
	default:
		close(s.done)
	}
	_ = s.ln.Close()
	s.wg.Wait()
}

func (s *Server) serve() {
	defer s.wg.Done()
	for {
		c, err := s.ln.Accept()
		if err != nil {
			select {
			case <-s.done:
				return
			default:
			}
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		s.conns.Add(1)
		go s.handle(c)
	}
}

func (s *Server) handle(c net.Conn) {
	defer c.Close() //nolint:errcheck // stub teardown
	for {
		pkt, err := ber.ReadPacket(c)
		if err != nil || len(pkt.Children) < 2 {
			return
		}
		msgID, _ := pkt.Children[0].Value.(int64)
		req := pkt.Children[1]
		switch req.Tag {
		case appBindRequest:
			s.binds.Add(1)
			code := resultSuccess
			if len(req.Children) >= 3 {
				dn, _ := req.Children[1].Value.(string)
				pw := ""
				if req.Children[2].ClassType == ber.ClassContext && req.Children[2].Tag == 0 {
					pw = string(req.Children[2].Data.Bytes())
				}
				if dn != "" {
					switch {
					case s.opts.RejectBind:
						code = resultInvalidCredentials
					case s.opts.BindDN != "" && (dn != s.opts.BindDN || pw != s.opts.BindPassword):
						code = resultInvalidCredentials
					}
				}
			}
			write(c, envelope(msgID, result(appBindResponse, code, "")))
		case appSearchRequest:
			base := ""
			if len(req.Children) > 0 {
				base, _ = req.Children[0].Value.(string)
			}
			if !s.baseKnown(base) {
				write(c, envelope(msgID, result(appSearchResultDone, resultNoSuchObject, "")))
				continue
			}
			entry := ber.Encode(ber.ClassApplication, ber.TypeConstructed, appSearchResultEntry, nil, "Search Result Entry")
			entry.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, base, "objectName"))
			entry.AppendChild(ber.NewSequence("attributes"))
			write(c, envelope(msgID, entry))
			write(c, envelope(msgID, result(appSearchResultDone, resultSuccess, "")))
		case appUnbindRequest:
			return
		case appExtendedRequest:
			write(c, envelope(msgID, result(appExtendedResponse, resultUnwillingToPerform, "stub: extended operations unsupported")))
		default:
			write(c, envelope(msgID, result(appSearchResultDone, resultProtocolError, "stub: unsupported operation")))
		}
	}
}

func (s *Server) baseKnown(base string) bool {
	if len(s.opts.KnownBases) == 0 {
		return true
	}
	for _, b := range s.opts.KnownBases {
		if b == base {
			return true
		}
	}
	return false
}

func envelope(msgID int64, op *ber.Packet) *ber.Packet {
	p := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Message")
	p.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, msgID, "Message ID"))
	p.AppendChild(op)
	return p
}

func result(tag ber.Tag, code int, diag string) *ber.Packet {
	p := ber.Encode(ber.ClassApplication, ber.TypeConstructed, tag, nil, "LDAP Result")
	p.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, code, "resultCode"))
	p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "matchedDN"))
	p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, diag, "diagnosticMessage"))
	return p
}

func write(c net.Conn, p *ber.Packet) {
	_, _ = c.Write(p.Bytes())
}
