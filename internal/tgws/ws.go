package tgws

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

// A WebSocket client for the binary messages of /apiws: just what the
// bridge needs (RFC 6455, client side, no extensions).

const (
	opCont   = 0x0
	opText   = 0x1
	opBinary = 0x2
	opClose  = 0x8
	opPing   = 0x9
	opPong   = 0xa

	maxMessage = 16 << 20
)

// wsConn is one WebSocket connection. Send may be called from one
// goroutine and Recv from another.
type wsConn struct {
	c    net.Conn
	br   *bufio.Reader
	wmu  sync.Mutex
	frag []byte
}

// HandshakeError is a refused upgrade («302»: this route does not serve
// WebSocket for the data center).
type HandshakeError struct {
	Status int
	Line   string
}

func (e *HandshakeError) Error() string { return "WebSocket: " + e.Line }

// wsTarget is where a WebSocket connection goes: TCP to Addr, TLS with
// SNI (fronting: a name other than Host; the certificate must still be
// Host's), HTTP Host and Path.
type wsTarget struct {
	Addr  string // ip:443
	Host  string // kws2.web.telegram.org
	SNI   string // "" = Host
	Path  string
	Roots *x509.CertPool // nil = the system's
}

// dialWS opens a WebSocket connection through dial (the TCP connection).
func dialWS(ctx context.Context, dial func(ctx context.Context, network, addr string) (net.Conn, error), t wsTarget) (*wsConn, error) {
	raw, err := dial(ctx, "tcp", t.Addr)
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			raw.Close()
		}
	}()
	if dl, has := ctx.Deadline(); has {
		raw.SetDeadline(dl)
	}
	sni := t.SNI
	if sni == "" {
		sni = t.Host
	}
	cfg := &tls.Config{ServerName: sni, RootCAs: t.Roots, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}}
	if sni != t.Host {
		// Fronting: the server answers with Host's certificate; it is
		// checked against Host, not the name sent.
		cfg.InsecureSkipVerify = true
		cfg.VerifyConnection = func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("no certificate")
			}
			opts := x509.VerifyOptions{DNSName: t.Host, Roots: t.Roots, Intermediates: x509.NewCertPool()}
			for _, c := range cs.PeerCertificates[1:] {
				opts.Intermediates.AddCert(c)
			}
			_, err := cs.PeerCertificates[0].Verify(opts)
			return err
		}
	}
	tc := tls.Client(raw, cfg)
	if err := tc.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	var nonce [16]byte
	rand.Read(nonce[:])
	key := base64.StdEncoding.EncodeToString(nonce[:])
	req := "GET " + t.Path + " HTTP/1.1\r\nHost: " + t.Host + "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Key: " + key + "\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: binary\r\n\r\n"
	if _, err := io.WriteString(tc, req); err != nil {
		return nil, err
	}
	br := bufio.NewReaderSize(tc, 64<<10)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		return nil, fmt.Errorf("WebSocket: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		return nil, &HandshakeError{Status: resp.StatusCode, Line: resp.Status}
	}
	raw.SetDeadline(time.Time{})
	ok = true
	return &wsConn{c: tc, br: br}, nil
}

func frame(op byte, payload []byte) []byte {
	n := len(payload)
	h := make([]byte, 0, 14+n)
	h = append(h, 0x80|op)
	switch {
	case n < 126:
		h = append(h, 0x80|byte(n))
	case n < 1<<16:
		h = append(h, 0x80|126, byte(n>>8), byte(n))
	default:
		h = append(h, 0x80|127)
		h = binary.BigEndian.AppendUint64(h, uint64(n))
	}
	var mask [4]byte
	rand.Read(mask[:])
	h = append(h, mask[:]...)
	start := len(h)
	h = append(h, payload...)
	for i := range n {
		h[start+i] ^= mask[i&3]
	}
	return h
}

// Send sends each part as a binary message, in one write.
func (w *wsConn) Send(parts ...[]byte) error {
	var buf []byte
	for _, p := range parts {
		buf = append(buf, frame(opBinary, p)...)
	}
	w.wmu.Lock()
	defer w.wmu.Unlock()
	_, err := w.c.Write(buf)
	return err
}

func (w *wsConn) control(op byte, payload []byte) {
	w.wmu.Lock()
	defer w.wmu.Unlock()
	w.c.SetWriteDeadline(time.Now().Add(5 * time.Second))
	w.c.Write(frame(op, payload))
	w.c.SetWriteDeadline(time.Time{})
}

// Recv returns the next binary message; io.EOF when the server closed.
func (w *wsConn) Recv() ([]byte, error) {
	for {
		var hdr [2]byte
		if _, err := io.ReadFull(w.br, hdr[:]); err != nil {
			return nil, err
		}
		fin, op := hdr[0]&0x80 != 0, hdr[0]&0x0f
		n := uint64(hdr[1] & 0x7f)
		switch n {
		case 126:
			var b [2]byte
			if _, err := io.ReadFull(w.br, b[:]); err != nil {
				return nil, err
			}
			n = uint64(binary.BigEndian.Uint16(b[:]))
		case 127:
			var b [8]byte
			if _, err := io.ReadFull(w.br, b[:]); err != nil {
				return nil, err
			}
			n = binary.BigEndian.Uint64(b[:])
		}
		if n > maxMessage {
			return nil, fmt.Errorf("WebSocket: a frame of %d bytes", n)
		}
		var mask [4]byte
		masked := hdr[1]&0x80 != 0
		if masked {
			if _, err := io.ReadFull(w.br, mask[:]); err != nil {
				return nil, err
			}
		}
		p := make([]byte, n)
		if _, err := io.ReadFull(w.br, p); err != nil {
			return nil, err
		}
		if masked {
			for i := range p {
				p[i] ^= mask[i&3]
			}
		}
		switch op {
		case opClose:
			code := p
			if len(code) > 2 {
				code = code[:2]
			}
			w.control(opClose, code)
			return nil, io.EOF
		case opPing:
			w.control(opPong, p)
			continue
		case opPong:
			continue
		case opCont, opText, opBinary:
			if fin && len(w.frag) == 0 {
				return p, nil
			}
			w.frag = append(w.frag, p...)
			if len(w.frag) > maxMessage {
				return nil, errors.New("WebSocket: a message too large")
			}
			if !fin {
				continue
			}
			m := w.frag
			w.frag = nil
			return m, nil
		}
	}
}

// Close sends a close frame and closes the connection.
func (w *wsConn) Close() error {
	w.control(opClose, nil)
	return w.c.Close()
}
