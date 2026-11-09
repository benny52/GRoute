package tgws

import (
	"bufio"
	"bytes"
	"context"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ---- the client side, as Telegram does it ----

type tgClient struct {
	c        net.Conn
	enc, dec cipher.Stream
	proto    uint32
}

func secretKey(k, secret []byte) []byte {
	if secret == nil {
		return k
	}
	h := sha256.Sum256(append(slices.Clone(k), secret...))
	return h[:]
}

// dialClient connects to addr and sends an init for dcIdx as Telegram
// would with a proxy secret (nil: none).
func dialClient(t *testing.T, addr string, secret []byte, proto uint32, dcIdx int16) *tgClient {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	init := make([]byte, 64)
	for {
		rand.Read(init)
		if !reservedStart(init) {
			break
		}
	}
	enc := ctr(secretKey(init[8:40], secret), init[40:56])
	ks := make([]byte, 64)
	enc.XORKeyStream(ks, make([]byte, 64))
	var tail [8]byte
	binary.LittleEndian.PutUint32(tail[:], proto)
	binary.LittleEndian.PutUint16(tail[4:], uint16(dcIdx))
	for i := range tail {
		init[56+i] = tail[i] ^ ks[56+i]
	}
	rev := reversed(init[8:56])
	dec := ctr(secretKey(rev[:32], secret), rev[32:])
	if _, err := c.Write(init); err != nil {
		t.Fatal(err)
	}
	return &tgClient{c: c, enc: enc, dec: dec, proto: proto}
}

// packet frames payload in the client's transport.
func packet(proto uint32, payload []byte) []byte {
	if proto == ProtoAbridged {
		n := len(payload) / 4
		if n < 0x7f {
			return append([]byte{byte(n)}, payload...)
		}
		return append([]byte{0x7f, byte(n), byte(n >> 8), byte(n >> 16)}, payload...)
	}
	return append(binary.LittleEndian.AppendUint32(nil, uint32(len(payload))), payload...)
}

func (tc *tgClient) send(t *testing.T, plain []byte) {
	t.Helper()
	b := make([]byte, len(plain))
	tc.enc.XORKeyStream(b, plain)
	if _, err := tc.c.Write(b); err != nil {
		t.Fatal(err)
	}
}

func (tc *tgClient) recv(t *testing.T, n int) []byte {
	t.Helper()
	tc.c.SetReadDeadline(time.Now().Add(10 * time.Second))
	b := make([]byte, n)
	if _, err := io.ReadFull(tc.c, b); err != nil {
		t.Fatal(err)
	}
	tc.dec.XORKeyStream(b, b)
	return b
}

// ---- a fake Telegram: WebSocket over TLS and plain TCP, echoing packets ----

type fakeTG struct {
	t         *testing.T
	ln        net.Listener
	tcp       net.Listener
	roots     *x509.CertPool
	cfg       *tls.Config
	mu        sync.Mutex
	refuse    map[string]int  // Host → HTTP status instead of 101
	blockSNI  map[string]bool // names whose TLS is cut (DPI)
	accepts   atomic.Int32    // WebSocket upgrades
	inits     []initSeen      // relay inits seen
	unaligned atomic.Int32    // WebSocket messages that were not one packet
	tcpConns  atomic.Int32
	raw       net.Listener    // a plain echo: web.telegram.org and the like
	silent    map[string]bool // Hosts whose WebSocket never answers
}

type initSeen struct {
	dc    int16
	proto uint32
	via   string // "ws" or "tcp"
	host  string
	query string // the WebSocket URL's query (a Worker's dst)
}

func newFakeTG(t *testing.T, certFor ...string) *fakeTG {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fake telegram"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), DNSNames: certFor,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, IsCA: true, BasicConstraintsValid: true,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	f := &fakeTG{t: t, roots: x509.NewCertPool(), refuse: map[string]int{}, blockSNI: map[string]bool{}, silent: map[string]bool{}}
	f.roots.AddCert(cert)
	f.cfg = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			if f.blockSNI[h.ServerName] {
				return nil, errors.New("blocked")
			}
			return nil, nil
		}}
	f.ln, _ = net.Listen("tcp", "127.0.0.1:0")
	f.tcp, _ = net.Listen("tcp", "127.0.0.1:0")
	f.raw, _ = net.Listen("tcp", "127.0.0.1:0")
	go f.serveWS()
	go f.serveTCP()
	go func() {
		for {
			c, err := f.raw.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()
	t.Cleanup(func() { f.ln.Close(); f.tcp.Close(); f.raw.Close() })
	return f
}

// dial routes the bridge's dials: the WebSocket address and any name
// (Cloudflare's) to the TLS listener, a data center's address to the TCP
// one.
func (f *fakeTG) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	var d net.Dialer
	host, _, _ := net.SplitHostPort(addr)
	if _, err := netip.ParseAddr(host); err != nil || strings.HasPrefix(addr, "127.0.0.1:") || strings.HasPrefix(addr, "127.0.0.2:") {
		return d.DialContext(ctx, network, f.ln.Addr().String())
	}
	if addr == webAddr {
		return d.DialContext(ctx, network, f.raw.Addr().String())
	}
	return d.DialContext(ctx, network, f.tcp.Addr().String())
}

func (f *fakeTG) serveWS() {
	for {
		c, err := f.ln.Accept()
		if err != nil {
			return
		}
		go f.handleWS(tls.Server(c, f.cfg))
	}
}

func (f *fakeTG) serveTCP() {
	for {
		c, err := f.tcp.Accept()
		if err != nil {
			return
		}
		f.tcpConns.Add(1)
		go f.handleTCP(c)
	}
}

// serverSide reads a relay init: the ciphers and what it says.
func serverSide(init []byte) (dec, enc cipher.Stream, proto uint32, dc int16) {
	dec = ctr(init[8:40], init[40:56])
	plain := make([]byte, 64)
	dec.XORKeyStream(plain, init)
	rev := reversed(init[8:56])
	enc = ctr(rev[:32], rev[32:])
	return dec, enc, binary.LittleEndian.Uint32(plain[56:]), int16(binary.LittleEndian.Uint16(plain[60:]))
}

func (f *fakeTG) handleTCP(c net.Conn) {
	defer c.Close()
	init := make([]byte, 64)
	if _, err := io.ReadFull(c, init); err != nil {
		return
	}
	dec, enc, proto, dc := serverSide(init)
	f.mu.Lock()
	f.inits = append(f.inits, initSeen{dc: dc, proto: proto, via: "tcp"})
	f.mu.Unlock()
	buf := make([]byte, 4096)
	for {
		n, err := c.Read(buf)
		if n > 0 {
			p := buf[:n]
			dec.XORKeyStream(p, p)
			p = answer(p)
			enc.XORKeyStream(p, p)
			c.Write(p)
		}
		if err != nil {
			return
		}
	}
}

func (f *fakeTG) handleWS(c *tls.Conn) {
	defer c.Close()
	br := bufio.NewReader(c)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	f.mu.Lock()
	status := f.refuse[req.Host]
	f.mu.Unlock()
	if status != 0 {
		io.WriteString(c, "HTTP/1.1 302 Found\r\nLocation: https://web.telegram.org/\r\nContent-Length: 0\r\n\r\n")
		return
	}
	if req.Header.Get("Sec-WebSocket-Protocol") != "binary" || req.URL.Path != "/apiws" {
		io.WriteString(c, "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
		return
	}
	h := sha1.Sum([]byte(req.Header.Get("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	io.WriteString(c, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Protocol: binary\r\n"+
		"Sec-WebSocket-Accept: "+base64.StdEncoding.EncodeToString(h[:])+"\r\n\r\n")
	f.accepts.Add(1)
	init, err := readFrame(br)
	if err != nil || len(init) != 64 {
		return
	}
	dec, enc, proto, dc := serverSide(init)
	f.mu.Lock()
	f.inits = append(f.inits, initSeen{dc: dc, proto: proto, via: "ws", host: req.Host, query: req.URL.RawQuery})
	silent := f.silent[req.Host]
	f.mu.Unlock()
	if silent {
		io.Copy(io.Discard, br)
		return
	}
	for {
		m, err := readFrame(br)
		if err != nil {
			return
		}
		dec.XORKeyStream(m, m)
		// One message, one packet.
		sp := newSplitter(proto)
		if parts := sp.add(m, m); len(parts) != 1 || len(parts[0]) != len(m) {
			f.unaligned.Add(1)
		}
		m = answer(m)
		enc.XORKeyStream(m, m)
		c.Write(serverFrame(m))
	}
}

func readFrame(br *bufio.Reader) ([]byte, error) {
	var h [2]byte
	if _, err := io.ReadFull(br, h[:]); err != nil {
		return nil, err
	}
	if h[1]&0x80 == 0 {
		return nil, errors.New("a client frame not masked")
	}
	n := uint64(h[1] & 0x7f)
	switch n {
	case 126:
		var b [2]byte
		io.ReadFull(br, b[:])
		n = uint64(binary.BigEndian.Uint16(b[:]))
	case 127:
		var b [8]byte
		io.ReadFull(br, b[:])
		n = binary.BigEndian.Uint64(b[:])
	}
	var mask [4]byte
	io.ReadFull(br, mask[:])
	p := make([]byte, n)
	if _, err := io.ReadFull(br, p); err != nil {
		return nil, err
	}
	for i := range p {
		p[i] ^= mask[i&3]
	}
	if h[0]&0x0f == opClose {
		return nil, io.EOF
	}
	return p, nil
}

func serverFrame(p []byte) []byte {
	h := []byte{0x80 | opBinary}
	switch n := len(p); {
	case n < 126:
		h = append(h, byte(n))
	case n < 1<<16:
		h = append(h, 126, byte(n>>8), byte(n))
	default:
		h = append(h, 127)
		h = binary.BigEndian.AppendUint64(h, uint64(n))
	}
	return append(h, p...)
}

// answer is a fake Telegram's reply to a plain packet: resPQ to
// req_pq_multi (intermediate transport), the packet itself otherwise.
func answer(plain []byte) []byte {
	if len(plain) == 44 && binary.LittleEndian.Uint32(plain[24:]) == 0xbe7e8ef1 {
		a := binary.LittleEndian.AppendUint32(nil, 56)
		a = append(a, make([]byte, 8)...)
		a = binary.LittleEndian.AppendUint64(a, 1)
		a = binary.LittleEndian.AppendUint32(a, 36)
		a = binary.LittleEndian.AppendUint32(a, 0x05162463)
		a = append(a, plain[28:44]...) // the nonce
		return append(a, make([]byte, 16)...)
	}
	return plain
}

func (f *fakeTG) seen() []initSeen {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.inits)
}

var kwsNames = []string{"kws1.web.telegram.org", "kws2.web.telegram.org", "kws2-1.web.telegram.org", "kws4.web.telegram.org", "kws4-1.web.telegram.org"}

// startProxy runs a proxy with a bridge over f.
func startProxy(t *testing.T, f *fakeTG, cfg Config) (*Proxy, *Bridge, []byte) {
	t.Helper()
	cfg.Dial, cfg.Roots = f.dial, f.roots
	if cfg.Redirect == nil {
		cfg.Redirect = map[int]netip.Addr{2: netip.MustParseAddr("127.0.0.1"), 4: netip.MustParseAddr("127.0.0.1")}
	}
	b := New(cfg)
	secret := NewSecret()
	p := &Proxy{Bridge: b, Secret: secret}
	if err := p.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.Close(); b.Close() })
	return p, b, secret
}

// echo sends packets and expects them back.
func echo(t *testing.T, tc *tgClient, sizes ...int) {
	t.Helper()
	var want []byte
	for _, n := range sizes {
		payload := make([]byte, n)
		rand.Read(payload)
		pk := packet(tc.proto, payload)
		want = append(want, pk...)
		// Split across writes, as TCP may.
		half := len(pk) / 2
		tc.send(t, pk[:half])
		tc.send(t, pk[half:])
	}
	if got := tc.recv(t, len(want)); !bytes.Equal(got, want) {
		t.Fatalf("echo differs")
	}
}

// ---- tests ----

func TestHello(t *testing.T) {
	secret := NewSecret()
	for _, c := range []struct {
		idx         int16
		dc          int
		media, test bool
		proto       uint32
	}{{2, 2, false, false, ProtoPadded}, {-4, 4, true, false, ProtoIntermediate}, {10002, 2, false, true, ProtoAbridged}, {-10001, 1, true, true, ProtoPadded}} {
		ln, _ := net.Listen("tcp", "127.0.0.1:0")
		done := make(chan []byte, 1)
		go func() {
			s, _ := ln.Accept()
			b := make([]byte, 64)
			io.ReadFull(s, b)
			done <- b
			s.Close()
		}()
		tc := dialClient(t, ln.Addr().String(), secret, c.proto, c.idx)
		init := <-done
		tc.c.Close()
		ln.Close()
		h, ok := ReadHello(init, secret)
		if !ok || h.DC != c.dc || h.Media != c.media || h.Test != c.test || h.Proto != c.proto {
			t.Fatalf("%+v: %+v %v", c, h, ok)
		}
		if _, ok := ReadHello(init, NewSecret()); ok {
			t.Fatal("a wrong secret decoded")
		}
		if dcIndex(h.DC, h.Media, h.Test) != c.idx {
			t.Fatalf("%d", dcIndex(h.DC, h.Media, h.Test))
		}
	}
	// The relay's init: a server reads what was put in, never a reserved start.
	for range 200 {
		init, _, _ := relayInit(ProtoAbridged, -2)
		if reservedStart(init) {
			t.Fatal("reserved")
		}
		_, _, proto, dc := serverSide(init)
		if proto != ProtoAbridged || dc != -2 {
			t.Fatalf("%x %d", proto, dc)
		}
	}
}

func TestSplitter(t *testing.T) {
	for _, proto := range []uint32{ProtoAbridged, ProtoIntermediate, ProtoPadded} {
		var stream []byte
		var lens []int
		for _, n := range []int{4, 40, 600, 0x7f * 4, 70000} {
			pk := packet(proto, make([]byte, n))
			stream = append(stream, pk...)
			lens = append(lens, len(pk))
		}
		s := newSplitter(proto)
		var got []int
		for i := 0; i < len(stream); i += 333 {
			for _, p := range s.add(stream[i:min(i+333, len(stream))], stream[i:min(i+333, len(stream))]) {
				got = append(got, len(p))
			}
		}
		if !slices.Equal(got, lens) || s.flush() != nil {
			t.Fatalf("%x: %v, want %v", proto, got, lens)
		}
	}
	// Nonsense turns it off: the rest goes as it comes.
	s := newSplitter(ProtoIntermediate)
	if parts := s.add([]byte{0, 0, 0, 0, 1, 2}, []byte{0, 0, 0, 0, 1, 2}); len(parts) != 1 || !s.disabled {
		t.Fatalf("%v", parts)
	}
	if parts := s.add([]byte{9}, []byte{9}); len(parts) != 1 {
		t.Fatal(parts)
	}
}

func TestBridgeWebSocket(t *testing.T) {
	f := newFakeTG(t, kwsNames...)
	p, b, secret := startProxy(t, f, Config{NoFronting: true, PoolSize: -1})
	for _, c := range []struct {
		proto uint32
		idx   int16
		host  string
	}{{ProtoPadded, 2, "kws2.web.telegram.org"}, {ProtoAbridged, -4, "kws4-1.web.telegram.org"}, {ProtoIntermediate, 4, "kws4.web.telegram.org"}} {
		tc := dialClient(t, p.Addr().String(), secret, c.proto, c.idx)
		echo(t, tc, 16, 1024, 300000, 8)
		tc.c.Close()
		s := f.seen()
		if last := s[len(s)-1]; last.via != "ws" || last.dc != c.idx || last.proto != c.proto || last.host != c.host {
			t.Fatalf("%+v", last)
		}
	}
	if n := f.unaligned.Load(); n != 0 {
		t.Fatalf("%d messages not one packet", n)
	}
	st := b.Stats()
	if st.Routes[RouteWS] != 3 || st.Bad != 0 || st.Failed != 0 || st.Up == 0 || st.Down == 0 {
		t.Fatalf("%+v", st)
	}
	// A wrong secret: nothing goes to Telegram.
	before := f.accepts.Load()
	tc := dialClient(t, p.Addr().String(), NewSecret(), ProtoPadded, 2)
	tc.send(t, []byte("xxxx"))
	time.Sleep(100 * time.Millisecond)
	tc.c.Close()
	if b.Stats().Bad != 1 || f.accepts.Load() != before {
		t.Fatalf("%+v", b.Stats())
	}
}

// The name kws2.web.telegram.org cut by DPI: the fronted name goes, the
// certificate still checked against kws2's.
func TestBridgeFronting(t *testing.T) {
	f := newFakeTG(t, kwsNames...)
	f.blockSNI["kws2.web.telegram.org"] = true
	p, b, secret := startProxy(t, f, Config{PoolSize: -1})
	tc := dialClient(t, p.Addr().String(), secret, ProtoPadded, 2)
	echo(t, tc, 100)
	tc.c.Close()
	if st := b.Stats(); st.Routes[RouteFronted] != 1 || !b.fronted.Load() {
		t.Fatalf("%+v", st)
	}
	// As real Telegram does: to the fronted name it presents its default
	// certificate, telegram.org's. Taken.
	h := newFakeTG(t, "telegram.org", "*.telegram.org")
	h.blockSNI["kws2.web.telegram.org"] = true
	p3, b3, secret3 := startProxy(t, h, Config{PoolSize: -1})
	tc = dialClient(t, p3.Addr().String(), secret3, ProtoPadded, 2)
	echo(t, tc, 100)
	tc.c.Close()
	if st := b3.Stats(); st.Routes[RouteFronted] != 1 {
		t.Fatalf("%+v", st)
	}
	// A certificate not for kws2: refused, fronted or not.
	g := newFakeTG(t, "example.com")
	g.blockSNI["kws2.web.telegram.org"] = true
	p2, b2, secret2 := startProxy(t, g, Config{PoolSize: -1})
	tc = dialClient(t, p2.Addr().String(), secret2, ProtoPadded, 2)
	tc.send(t, packet(ProtoPadded, make([]byte, 8)))
	time.Sleep(300 * time.Millisecond)
	if st := b2.Stats(); st.Routes[RouteFronted] != 0 || st.Routes[RouteWS] != 0 || g.accepts.Load() != 0 {
		t.Fatalf("%+v", st)
	}
	tc.c.Close()
}

// No WebSocket for the data center (302, or none at all): the VPN, then
// direct TCP; the stream is the same.
func TestBridgeFallbacks(t *testing.T) {
	f := newFakeTG(t, kwsNames...)
	f.refuse["kws4.web.telegram.org"] = 302
	var vpnCalls atomic.Int32
	vpnUp := atomic.Bool{}
	vpnUp.Store(true)
	p, b, secret := startProxy(t, f, Config{NoFronting: true, PoolSize: -1,
		VPN: func(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
			vpnCalls.Add(1)
			if dst != netip.MustParseAddrPort("149.154.167.91:443") && dst != netip.MustParseAddrPort("149.154.175.50:443") {
				t.Errorf("VPN to %v", dst)
			}
			if !vpnUp.Load() {
				return nil, errors.New("tunnel down")
			}
			var d net.Dialer
			return d.DialContext(ctx, "tcp", f.tcp.Addr().String())
		}})
	tc := dialClient(t, p.Addr().String(), secret, ProtoIntermediate, 4)
	echo(t, tc, 64, 5000)
	tc.c.Close()
	// DC1: no WebSocket address at all.
	tc = dialClient(t, p.Addr().String(), secret, ProtoIntermediate, 1)
	echo(t, tc, 64)
	tc.c.Close()
	if st := b.Stats(); st.Routes[RouteVPN] != 2 || vpnCalls.Load() != 2 {
		t.Fatalf("%+v", st)
	}
	// The VPN down: direct TCP.
	vpnUp.Store(false)
	tc = dialClient(t, p.Addr().String(), secret, ProtoIntermediate, 4)
	echo(t, tc, 64)
	tc.c.Close()
	if st := b.Stats(); st.Routes[RouteTCP] != 1 {
		t.Fatalf("%+v", st)
	}
	for _, s := range f.seen() {
		if s.via == "tcp" && s.dc != 4 && s.dc != 1 {
			t.Fatalf("%+v", s)
		}
	}
}

// Nothing reachable: the client is closed, the failure counted, and the
// direct address is not dialed again at once.
func TestBridgeNoRoute(t *testing.T) {
	var dials atomic.Int32
	b := New(Config{NoFronting: true, PoolSize: -1, Redirect: map[int]netip.Addr{},
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dials.Add(1)
			return nil, errors.New("refused")
		}})
	defer b.Close()
	p := &Proxy{Bridge: b, Secret: NewSecret()}
	if err := p.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	for range 2 {
		tc := dialClient(t, p.Addr().String(), p.Secret, ProtoPadded, 2)
		tc.c.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := tc.c.Read(make([]byte, 1)); err == nil {
			t.Fatal("not closed")
		}
		tc.c.Close()
	}
	if st := b.Stats(); st.Failed != 2 || !strings.Contains(st.LastError, "недоступен") || dials.Load() != 1 {
		t.Fatalf("%+v dials=%d", st, dials.Load())
	}
}

// The pool opens connections ahead; a client takes one at once.
func TestBridgePool(t *testing.T) {
	f := newFakeTG(t, kwsNames...)
	p, b, secret := startProxy(t, f, Config{NoFronting: true, PoolSize: 2, Redirect: map[int]netip.Addr{2: netip.MustParseAddr("127.0.0.1")}})
	b.Warm()
	deadline := time.Now().Add(5 * time.Second)
	for f.accepts.Load() < 4 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if f.accepts.Load() != 4 { // DC2 and its media, two each
		t.Fatalf("%d", f.accepts.Load())
	}
	tc := dialClient(t, p.Addr().String(), secret, ProtoPadded, 2)
	echo(t, tc, 32)
	tc.c.Close()
	// Taken from the pool and topped up again.
	for f.accepts.Load() < 5 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if f.accepts.Load() != 5 {
		t.Fatalf("%d", f.accepts.Load())
	}
	// Old ones are not used.
	old := poolMaxAge
	poolMaxAge = 0
	defer func() { poolMaxAge = old }()
	tc = dialClient(t, p.Addr().String(), secret, ProtoPadded, 2)
	echo(t, tc, 32)
	tc.c.Close()
}

func TestLinkAndSecret(t *testing.T) {
	s, err := ParseSecret("dd0123456789abcdef0123456789ABCDEF")
	if err != nil || len(s) != 16 {
		t.Fatal(err)
	}
	if _, err := ParseSecret("abc"); err == nil {
		t.Fatal("short")
	}
	if l := Link("127.0.0.1", 1443, s); l != "tg://proxy?port=1443&secret=dd0123456789abcdef0123456789abcdef&server=127.0.0.1" {
		t.Fatal(l)
	}
}

const webAddr = "149.154.167.99:443"

// transparent serves each accepted connection as the engine would hand it
// over, on its way to dst.
func transparent(t *testing.T, b *Bridge, dst string) string {
	t.Helper()
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go b.ServeTransparent(context.Background(), c, netip.MustParseAddrPort(dst))
		}
	}()
	return ln.Addr().String()
}

// Telegram with no proxy set: its own connection (no secret) goes over
// WebSocket; anything else, and everything once WebSocket is down, goes
// on unchanged to where it was going.
func TestTransparent(t *testing.T) {
	f := newFakeTG(t, kwsNames...)
	b := New(Config{NoFronting: true, PoolSize: -1, Dial: f.dial, Roots: f.roots,
		Redirect: map[int]netip.Addr{2: netip.MustParseAddr("127.0.0.1"), 4: netip.MustParseAddr("127.0.0.1")}})
	defer b.Close()
	dc := transparent(t, b, "149.154.167.51:443")
	tc := dialClient(t, dc, nil, ProtoAbridged, 2)
	echo(t, tc, 64, 2000)
	tc.c.Close()
	if s := f.seen(); len(s) != 1 || s[0].via != "ws" || s[0].dc != 2 {
		t.Fatalf("%+v", s)
	}
	// web.telegram.org's TLS: passed on as it is.
	web := transparent(t, b, webAddr)
	c, _ := net.Dial("tcp", web)
	hello := append([]byte{0x16, 3, 1, 2, 0}, bytes.Repeat([]byte{7}, 200)...)
	c.Write(hello)
	got := make([]byte, len(hello))
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(c, got); err != nil || !bytes.Equal(got, hello) {
		t.Fatalf("%v", err)
	}
	c.Close()
	// A data center without WebSocket: passed on, its own init and all.
	dc1 := transparent(t, b, "149.154.175.50:443")
	tc = dialClient(t, dc1, nil, ProtoIntermediate, 1)
	echo(t, tc, 32)
	tc.c.Close()
	if s := f.seen(); len(s) != 2 || s[1].via != "tcp" || s[1].dc != 1 {
		t.Fatalf("%+v", s)
	}
	if st := b.Stats(); st.Routes[RouteWS] != 1 || st.Routes[RouteTCP] != 2 {
		t.Fatalf("%+v", st)
	}
}

// Self-checks: WebSocket answering, then not (connections skip it at once
// and say which fallback answers), then answering again.
func TestCheck(t *testing.T) {
	f := newFakeTG(t, kwsNames...)
	var vpn atomic.Int32
	b := New(Config{NoFronting: true, PoolSize: -1, Dial: f.dial, Roots: f.roots,
		Redirect: map[int]netip.Addr{2: netip.MustParseAddr("127.0.0.1"), 4: netip.MustParseAddr("127.0.0.1")},
		VPN: func(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
			vpn.Add(1)
			var d net.Dialer
			return d.DialContext(ctx, "tcp", f.tcp.Addr().String())
		}})
	defer b.Close()
	if b.Health() != nil {
		t.Fatal("health before a check")
	}
	h := b.Check(context.Background())
	if !h.WS || h.WSRoute != RouteWS || h.Fallback != "" || b.wsDown.Load() || b.Health().At.IsZero() {
		t.Fatalf("%+v", h)
	}
	f.mu.Lock()
	f.refuse["kws2.web.telegram.org"], f.refuse["kws4.web.telegram.org"] = 302, 302
	f.mu.Unlock()
	h = b.Check(context.Background())
	if h.WS || !strings.Contains(h.WSError, "302") || h.Fallback != RouteVPN || !b.wsDown.Load() {
		t.Fatalf("%+v", h)
	}
	// WebSocket down: straight to the VPN, no upgrade tried.
	before := f.accepts.Load()
	dc := transparent(t, b, "149.154.167.51:443")
	tc := dialClient(t, dc, nil, ProtoAbridged, 2)
	echo(t, tc, 64)
	tc.c.Close()
	if f.accepts.Load() != before || b.Stats().Routes[RouteVPN] != 1 {
		t.Fatalf("%+v", b.Stats())
	}
	f.mu.Lock()
	f.refuse = map[string]int{}
	f.mu.Unlock()
	if h = b.Check(context.Background()); !h.WS || b.wsDown.Load() {
		t.Fatalf("%+v", h)
	}
	// Nothing answers: said.
	b2 := New(Config{NoFronting: true, PoolSize: -1, Redirect: map[int]netip.Addr{},
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) { return nil, errors.New("refused") }})
	if h := b2.Check(context.Background()); h.WS || h.Fallback != "" || !strings.Contains(h.FallbackError, "refused") {
		t.Fatalf("%+v", h)
	}
}
