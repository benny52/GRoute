package socks5

import (
	"context"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

var netipV4zero = netip.IPv4Unspecified()

// UDPNetwork supplies the outbound sockets and DNS for an association.
// A missing address family may return an error. The listener to the SOCKS
// client is independent and stays on loopback.
type UDPNetwork interface {
	ListenUDP(ipv6 bool) (net.PacketConn, error)
	ResolveUDP(context.Context, Addr) (*net.UDPAddr, error)
}

// Server supplies a loopback SOCKS5 endpoint. Custom TCP and UDP backends
// serve a userspace tunnel; the defaults use the host network for the stub.
type Server struct {
	Username, Password string
	// Dial overrides the outbound TCP dialer.
	Dial       func(network, addr string) (net.Conn, error)
	UDPNetwork UDPNetwork
	// OnConnect is called for every CONNECT request (logging, tests).
	OnConnect func(dst Addr)

	ln     net.Listener
	wg     sync.WaitGroup
	mu     sync.Mutex
	conn   map[net.Conn]struct{}
	closed bool // Close has run: a connection accepted later is dropped
}

// Listen starts serving on addr (e.g. "127.0.0.1:0").
func (s *Server) Listen(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	s.ln = ln
	s.conn = make(map[net.Conn]struct{})
	s.wg.Add(1)
	go s.serve()
	return nil
}

func (s *Server) Addr() string { return s.ln.Addr().String() }

func (s *Server) Close() error {
	err := s.ln.Close()
	s.mu.Lock()
	s.closed = true
	for c := range s.conn {
		c.Close()
	}
	s.mu.Unlock()
	s.wg.Wait()
	return err
}

func (s *Server) serve() {
	defer s.wg.Done()
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		// A connection Accept returned while Close ran would miss Close's
		// sweep and keep Close waiting for its handler forever.
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			c.Close()
			return
		}
		s.conn[c] = struct{}{}
		s.wg.Add(1)
		s.mu.Unlock()
		go func() {
			defer s.wg.Done()
			defer s.untrack(c)
			defer c.Close()
			s.handle(c)
		}()
	}
}

func (s *Server) untrack(c net.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.conn, c)
}

func (s *Server) handle(c net.Conn) {
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	var h [2]byte
	if _, err := io.ReadFull(c, h[:]); err != nil || h[0] != ver5 {
		return
	}
	methods := make([]byte, h[1])
	if _, err := io.ReadFull(c, methods); err != nil {
		return
	}
	want := byte(methodNone)
	if s.Username != "" {
		want = methodUserPass
	}
	ok := false
	for _, m := range methods {
		ok = ok || m == want
	}
	if !ok {
		c.Write([]byte{ver5, methodNoAccept})
		return
	}
	c.Write([]byte{ver5, want})
	if want == methodUserPass {
		if !s.auth(c) {
			return
		}
	}
	var r [3]byte
	if _, err := io.ReadFull(c, r[:]); err != nil {
		return
	}
	dst, err := readAddr(c)
	if err != nil {
		return
	}
	switch r[1] {
	case CmdConnect:
		s.connect(c, dst)
	case CmdUDPAssociate:
		s.associate(c, dst)
	default:
		reply(c, 7, Addr{})
	}
}

func (s *Server) auth(c net.Conn) bool {
	var h [2]byte
	if _, err := io.ReadFull(c, h[:]); err != nil {
		return false
	}
	u := make([]byte, h[1])
	if _, err := io.ReadFull(c, u); err != nil {
		return false
	}
	if _, err := io.ReadFull(c, h[:1]); err != nil {
		return false
	}
	p := make([]byte, h[0])
	if _, err := io.ReadFull(c, p); err != nil {
		return false
	}
	if string(u) != s.Username || string(p) != s.Password {
		c.Write([]byte{1, 1})
		return false
	}
	c.Write([]byte{1, 0})
	return true
}

func reply(c net.Conn, code byte, bound Addr) {
	if !bound.IP.IsValid() && bound.Host == "" {
		bound.IP = netipV4zero
	}
	b, _ := AppendAddr([]byte{ver5, code, 0}, bound)
	c.Write(b)
}

func (s *Server) connect(c net.Conn, dst Addr) {
	if s.OnConnect != nil {
		s.OnConnect(dst)
	}
	dial := s.Dial
	if dial == nil {
		dial = func(n, a string) (net.Conn, error) { return net.DialTimeout(n, a, 10*time.Second) }
	}
	up, err := dial("tcp", dst.String())
	if err != nil {
		reply(c, 5, Addr{})
		return
	}
	defer up.Close()
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.conn[up] = struct{}{}
	s.mu.Unlock()
	defer s.untrack(up)
	reply(c, 0, AddrFromAddrPort(up.LocalAddr().(*net.TCPAddr).AddrPort()))
	_ = c.SetDeadline(time.Time{})
	Pipe(c, up)
}

// associate relays UDP datagrams for one client until the control
// connection closes. The client talks to a socket on the control
// connection's address (loopback for the stub); the remotes to another one
// on any address: a socket bound to loopback cannot reach them.
func (s *Server) associate(c net.Conn, requested Addr) {
	pc, err := ListenUDP("udp", net.JoinHostPort(c.LocalAddr().(*net.TCPAddr).IP.String(), "0"))
	if err != nil {
		reply(c, 1, Addr{})
		return
	}
	defer pc.Close()
	network := s.UDPNetwork
	if network == nil {
		network = hostUDPNetwork{}
	}
	out := map[bool]net.PacketConn{}
	for _, ipv6 := range []bool{false, true} {
		if sock, err := network.ListenUDP(ipv6); err == nil {
			out[ipv6] = sock
		}
	}
	if len(out) == 0 {
		reply(c, 1, Addr{})
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	var workers sync.WaitGroup
	defer func() {
		cancel()
		c.Close()
		pc.Close()
		for _, sock := range out {
			sock.Close()
		}
		workers.Wait()
	}()
	reply(c, 0, AddrFromAddrPort(pc.LocalAddr().(*net.UDPAddr).AddrPort()))
	_ = c.SetDeadline(time.Time{})
	workers.Add(1)
	go func() {
		defer workers.Done()
		io.Copy(io.Discard, c)
		cancel()
		pc.Close()
	}()
	var client atomic.Pointer[net.UDPAddr]
	for _, sock := range out {
		workers.Add(1)
		go func() {
			defer workers.Done()
			// Replies from the remotes: wrapped and sent to the client.
			buf := make([]byte, 65535)
			for {
				n, remote, err := sock.ReadFrom(buf)
				if err != nil {
					return
				}
				to := client.Load()
				if to == nil {
					continue
				}
				from := remote.(*net.UDPAddr).AddrPort()
				from = netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
				hdr, _ := AppendAddr([]byte{0, 0, 0}, AddrFromAddrPort(from))
				pc.WriteToUDP(append(hdr, buf[:n]...), to)
			}
		}()
	}
	buf := make([]byte, 65535)
	for {
		n, from, err := pc.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if !from.IP.Equal(c.RemoteAddr().(*net.TCPAddr).IP) || (requested.Port != 0 && requested.Port != uint16(from.Port)) {
			continue
		}
		if cur := client.Load(); cur != nil && !(from.IP.Equal(cur.IP) && from.Port == cur.Port) {
			continue // only the first sender is the client
		}
		dst, payload, err := ParseUDPHeader(buf[:n])
		if err != nil {
			continue
		}
		client.Store(from)
		ua, err := network.ResolveUDP(ctx, dst)
		if err != nil {
			continue
		}
		if sock := out[ua.IP.To4() == nil]; sock != nil {
			sock.WriteTo(payload, ua)
		}
	}
}

type hostUDPNetwork struct{}

func (hostUDPNetwork) ListenUDP(ipv6 bool) (net.PacketConn, error) {
	network := "udp4"
	if ipv6 {
		network = "udp6"
	}
	return net.ListenUDP(network, nil)
}

func (hostUDPNetwork) ResolveUDP(ctx context.Context, dst Addr) (*net.UDPAddr, error) {
	ip := dst.IP
	if !ip.IsValid() {
		ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", dst.Host)
		if err != nil || len(ips) == 0 {
			return nil, &net.DNSError{Err: "host not found"}
		}
		ip = ips[0]
	}
	return net.UDPAddrFromAddrPort(netip.AddrPortFrom(ip, dst.Port)), nil
}

// Pipe copies both directions with half-close and returns when both
// directions are done. It returns bytes a->b and b->a. An error in either
// direction (as opposed to EOF) resets both (see Abort): a broken stream
// must not reach the other peer as a clean end of stream, where a
// truncated download would look complete.
func Pipe(a, b net.Conn) (ab, ba int64) {
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		var err error
		ba, err = io.Copy(a, b)
		finish(a, b, err)
	}()
	var err error
	ab, err = io.Copy(b, a)
	finish(b, a, err)
	wg.Wait()
	return ab, ba
}

func finish(dst, src net.Conn, err error) {
	if err != nil {
		Abort(dst)
		Abort(src)
		return
	}
	closeWrite(dst)
}

// Abort closes c with RST instead of FIN (SO_LINGER 0): the peer sees the
// connection reset, and nothing queued is sent afterwards. Wrappers are
// looked through with a NetConn method, as for crypto/tls.Conn.
func Abort(c net.Conn) {
	for inner := c; inner != nil; {
		if l, ok := inner.(interface{ SetLinger(int) error }); ok {
			_ = l.SetLinger(0)
			break
		}
		u, ok := inner.(interface{ NetConn() net.Conn })
		if !ok {
			break
		}
		inner = u.NetConn()
	}
	c.Close()
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		cw.CloseWrite()
		return
	}
	c.Close()
}
