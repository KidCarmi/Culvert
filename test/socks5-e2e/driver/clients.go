//go:build socks5_e2e

package main

// clients.go — the protocol clients. The SOCKS5 client is a raw RFC 1928 /
// RFC 1929 implementation so every reply byte is asserted exactly; the HTTP
// client writes a raw CONNECT for the same reason. golang.org/x/net/proxy and
// curl are run as independent, off-the-shelf clients on top.

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/net/proxy"
)

const probeTimeout = 8 * time.Second

// Observed outcomes. A probe reports exactly one.
const (
	obsTunnel         = "tunnel"                   // reply 0x00 / HTTP 200, and the echo round trip went through
	obsInspected      = "inspected-tls"            // HTTP 200, TLS leaf minted by Culvert's CA, upstream body received
	obsUninspectedTLS = "tunnel-tls-upstream-cert" // tunnel reached the upstream's OWN certificate: no inspection
	obsDropRST        = "drop-rst"                 // no reply; connection reset
	obsDropEOF        = "drop-eof"                 // no reply; orderly close
	obsAuthFail       = "auth-status-0x01"         // RFC 1929 failure status
	obsNoMethod       = "method-0xff"              // no acceptable authentication method
)

func obsReply(code byte) string { return fmt.Sprintf("reply-0x%02x", code) }
func obsStatus(code int) string { return fmt.Sprintf("status-%d", code) }

// verdictOf normalises an observed outcome for the cross-protocol comparison.
func verdictOf(obs string) string {
	switch {
	case obs == obsTunnel || obs == obsUninspectedTLS:
		return "ALLOW"
	case obs == obsInspected:
		return "INSPECT"
	case obs == obsDropRST || obs == obsDropEOF:
		return "DROP"
	case obs == obsAuthFail || obs == obsNoMethod || obs == obsStatus(407):
		return "AUTH_REFUSED"
	case strings.HasPrefix(obs, "reply-0x"), obs == obsStatus(403), obs == obsStatus(302):
		return "REFUSE"
	}
	return "OTHER(" + obs + ")"
}

// target is what a probe connects to through the proxy.
type target struct {
	host string // FQDN, or an IPv4 literal (sent as ATYP 0x01)
	port int
	tls  bool // the upstream speaks TLS (the inspection cases)
}

// probeEnv is what the tunnel checks need to classify a TLS peer.
type probeEnv struct {
	upstreamCA *x509.CertPool
	culvertCA  *x509.CertPool
}

// ── Raw SOCKS5 ──────────────────────────────────────────────────────────────

type socksOpts struct {
	cred    *cred
	methods []byte // methods offered in the greeting
}

// socks5Probe runs one RFC 1928 CONNECT through the SOCKS5 listener and, when
// the server replies 0x00, proves the tunnel works end to end.
func socks5Probe(addr string, o socksOpts, t target, pe probeEnv) (string, error) {
	conn, err := net.DialTimeout("tcp", addr, probeTimeout)
	if err != nil {
		return "", fmt.Errorf("dial socks5: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(probeTimeout))

	methods := o.methods
	if methods == nil {
		methods = []byte{0x00, 0x02} // what curl and most clients offer
	}
	greeting := append([]byte{0x05, byte(len(methods))}, methods...)
	if _, err := conn.Write(greeting); err != nil {
		return "", err
	}
	sel := make([]byte, 2)
	if _, err := io.ReadFull(conn, sel); err != nil {
		return classifyNoReply(err, "greeting")
	}
	if sel[0] != 0x05 {
		return "", fmt.Errorf("bad method-selection version 0x%02x", sel[0])
	}
	switch sel[1] {
	case 0xFF:
		return obsNoMethod, nil
	case 0x02:
		if o.cred == nil {
			return "", errors.New("server selected USER/PASS but the probe has no credential")
		}
		msg := []byte{0x01, byte(len(o.cred.User))}
		msg = append(msg, o.cred.User...)
		msg = append(msg, byte(len(o.cred.Pass)))
		msg = append(msg, o.cred.Pass...)
		if _, err := conn.Write(msg); err != nil {
			return "", err
		}
		st := make([]byte, 2)
		if _, err := io.ReadFull(conn, st); err != nil {
			return classifyNoReply(err, "auth")
		}
		if st[0] != 0x01 {
			return "", fmt.Errorf("bad RFC 1929 status version 0x%02x", st[0])
		}
		if st[1] != 0x00 {
			return obsAuthFail, nil
		}
	case 0x00:
		// NO-AUTH selected.
	default:
		return "", fmt.Errorf("unexpected method 0x%02x", sel[1])
	}

	req := []byte{0x05, 0x01, 0x00}
	if ip := net.ParseIP(t.host); ip != nil && ip.To4() != nil {
		req = append(req, 0x01)
		req = append(req, ip.To4()...)
	} else {
		req = append(req, 0x03, byte(len(t.host)))
		req = append(req, t.host...)
	}
	req = binary.BigEndian.AppendUint16(req, uint16(t.port))
	if _, err := conn.Write(req); err != nil {
		return "", err
	}
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return classifyNoReply(err, "request")
	}
	if hdr[0] != 0x05 {
		return "", fmt.Errorf("bad reply version 0x%02x", hdr[0])
	}
	var skip int
	switch hdr[3] {
	case 0x01:
		skip = 4 + 2
	case 0x04:
		skip = 16 + 2
	case 0x03:
		l := make([]byte, 1)
		if _, err := io.ReadFull(conn, l); err != nil {
			return "", err
		}
		skip = int(l[0]) + 2
	default:
		return "", fmt.Errorf("bad reply ATYP 0x%02x", hdr[3])
	}
	if _, err := io.ReadFull(conn, make([]byte, skip)); err != nil {
		return "", err
	}
	if hdr[1] != 0x00 {
		return obsReply(hdr[1]), nil
	}
	return tunnelCheck(conn, t, pe)
}

// classifyNoReply maps a read failure where a reply was due.
func classifyNoReply(err error, stage string) (string, error) {
	switch {
	case errors.Is(err, syscall.ECONNRESET):
		return obsDropRST, nil
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return obsDropEOF, nil
	}
	return "", fmt.Errorf("no reply at %s: %w", stage, err)
}

// tunnelCheck proves an established tunnel reaches the upstream: an echo round
// trip for the plain target, or a TLS handshake + HTTPS GET for a TLS target,
// classifying whose certificate the client was shown.
func tunnelCheck(conn net.Conn, t target, pe probeEnv) (string, error) {
	if !t.tls {
		nonce := fmt.Sprintf("e2e-echo-%d\n", time.Now().UnixNano())
		if _, err := io.WriteString(conn, nonce); err != nil {
			return "", fmt.Errorf("tunnel write: %w", err)
		}
		got := make([]byte, len(nonce))
		if _, err := io.ReadFull(conn, got); err != nil {
			return "", fmt.Errorf("tunnel echo read: %w", err)
		}
		if string(got) != nonce {
			return "", fmt.Errorf("tunnel echo mismatch: %q", got)
		}
		return obsTunnel, nil
	}
	// TLS target. Verification is done by hand below (against BOTH candidate
	// roots) because the point is to learn WHICH root signed the leaf: the
	// upstream's own CA (an uninspected tunnel) or Culvert's (inspected).
	tc := tls.Client(conn, &tls.Config{
		ServerName:         t.host,
		InsecureSkipVerify: true, //nolint:gosec // test-only; the chain is verified explicitly below against named roots
		MinVersion:         tls.VersionTLS12,
	})
	if err := tc.Handshake(); err != nil {
		return "", fmt.Errorf("tls handshake through tunnel: %w", err)
	}
	certs := tc.ConnectionState().PeerCertificates
	verify := func(pool *x509.CertPool) bool {
		if pool == nil || len(certs) == 0 {
			return false
		}
		inter := x509.NewCertPool()
		for _, c := range certs[1:] {
			inter.AddCert(c)
		}
		_, err := certs[0].Verify(x509.VerifyOptions{DNSName: t.host, Roots: pool, Intermediates: inter})
		return err == nil
	}
	byUpstream, byCulvert := verify(pe.upstreamCA), verify(pe.culvertCA)
	body, err := httpsGetOver(tc, t.host)
	if err != nil {
		return "", fmt.Errorf("https over tunnel: %w", err)
	}
	if body != upstreamTLSBody {
		return "", fmt.Errorf("https over tunnel: unexpected body %q", body)
	}
	switch {
	case byCulvert && !byUpstream:
		return obsInspected, nil
	case byUpstream && !byCulvert:
		return obsUninspectedTLS, nil
	}
	return "", fmt.Errorf("leaf (issuer %q) verified by upstream CA=%v, Culvert CA=%v", certs[0].Issuer.CommonName, byUpstream, byCulvert)
}

func httpsGetOver(conn net.Conn, host string) (string, error) {
	if _, err := fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", host); err != nil {
		return "", err
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return string(b), err
}

// ── Raw HTTP CONNECT ────────────────────────────────────────────────────────

// connectProbe sends one CONNECT through the HTTP proxy listener.
func connectProbe(addr string, c *cred, t target, pe probeEnv) (string, error) {
	conn, err := net.DialTimeout("tcp", addr, probeTimeout)
	if err != nil {
		return "", fmt.Errorf("dial proxy: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(probeTimeout))
	authority := net.JoinHostPort(t.host, strconv.Itoa(t.port))
	var b strings.Builder
	fmt.Fprintf(&b, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n", authority, authority)
	if c != nil {
		fmt.Fprintf(&b, "Proxy-Authorization: Basic %s\r\n", base64.StdEncoding.EncodeToString([]byte(c.User+":"+c.Pass)))
	}
	b.WriteString("\r\n")
	if _, err := io.WriteString(conn, b.String()); err != nil {
		return "", err
	}
	br := bufio.NewReader(conn)
	if _, err := br.Peek(1); err != nil {
		return classifyNoReply(err, "CONNECT response")
	}
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		return "", fmt.Errorf("read CONNECT response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return obsStatus(resp.StatusCode), nil
	}
	if br.Buffered() > 0 {
		return "", errors.New("bytes after the CONNECT response header")
	}
	return tunnelCheck(conn, t, pe)
}

// ── Off-the-shelf clients ───────────────────────────────────────────────────

// xnetProxyGet fetches http://host:port/ through golang.org/x/net/proxy's
// SOCKS5 dialer (domain names are sent unresolved, ATYP 0x03).
func xnetProxyGet(socksAddr string, c *cred, host string, port int) (string, error) {
	var auth *proxy.Auth
	if c != nil {
		auth = &proxy.Auth{User: c.User, Password: c.Pass}
	}
	d, err := proxy.SOCKS5("tcp", socksAddr, auth, &net.Dialer{Timeout: probeTimeout})
	if err != nil {
		return "", err
	}
	cd, ok := d.(proxy.ContextDialer)
	if !ok {
		return "", errors.New("x/net/proxy dialer has no DialContext")
	}
	cl := &http.Client{Timeout: probeTimeout, Transport: &http.Transport{Proxy: nil, DialContext: cd.DialContext}}
	resp, err := cl.Get(fmt.Sprintf("http://%s:%d/", host, port))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return string(b), err
}

// curlSocks fetches through curl --socks5-hostname. Returns the body, curl's
// exit code, and stderr.
func curlSocks(curl, socksAddr string, c *cred, host string, port int) (string, int, string) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*probeTimeout)
	defer cancel()
	args := []string{"-sS", "--max-time", "6", "--noproxy", "", "--socks5-hostname", socksAddr}
	if c != nil {
		args = append(args, "--proxy-user", c.User+":"+c.Pass)
	}
	args = append(args, fmt.Sprintf("http://%s:%d/", host, port))
	cmd := exec.CommandContext(ctx, curl, args...)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=/nonexistent"} // no proxy variables, no ~/.curlrc
	var out, errb strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		code = -1
	}
	return out.String(), code, strings.TrimSpace(errb.String())
}
