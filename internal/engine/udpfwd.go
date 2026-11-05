package engine

import (
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lardan099/hyroute/internal/packet"
)

// udpForwarder sends the Direct UDP of a TUN engine (Options.ReflectDirect)
// to the network: one socket on the physical interface per application
// socket (its address and port in the TUN), so a reply from any remote
// comes back to it (endpoint-independent, as games and STUN expect). The
// replies are written into the TUN device as datagrams from the remote.
type udpForwarder struct {
	// listen opens a socket on the physical interface for an IPv4 or IPv6
	// application socket.
	listen func(v6 bool) (*net.UDPConn, error)
	// deliver writes a packet into the TUN device.
	deliver func(pkt []byte)
	log     *slog.Logger
	idle    time.Duration // default 60s
	dnsIdle time.Duration // a socket that only spoke to port 53; default 10s
	max     int           // sockets; default 4096

	mu     sync.Mutex
	socks  map[netip.AddrPort]*fwdSock
	closed bool

	Sent, Recv, Dropped atomic.Int64
}

type fwdSock struct {
	conn    *net.UDPConn
	app     netip.AddrPort
	last    atomic.Int64 // unix nanos
	onlyDNS atomic.Bool
}

func (f *udpForwarder) init() {
	if f.idle == 0 {
		f.idle = 60 * time.Second
	}
	if f.dnsIdle == 0 {
		f.dnsIdle = 10 * time.Second
	}
	if f.max == 0 {
		f.max = 4096
	}
	if f.log == nil {
		f.log = slog.Default()
	}
}

// send forwards one datagram of the application (a parsed UDP packet).
func (f *udpForwarder) send(p *packet.Packet) {
	app, dst := p.Src(), p.Dst()
	s := f.sock(app)
	if s == nil {
		f.Dropped.Add(1)
		return
	}
	s.last.Store(time.Now().UnixNano())
	if dst.Port() != 53 {
		s.onlyDNS.Store(false)
	}
	if _, err := s.conn.WriteToUDPAddrPort(p.Payload(), dst); err != nil {
		f.Dropped.Add(1)
		return
	}
	f.Sent.Add(1)
}

func (f *udpForwarder) sock(app netip.AddrPort) *fwdSock {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return nil
	}
	if f.socks == nil {
		f.init()
		f.socks = map[netip.AddrPort]*fwdSock{}
	}
	if s := f.socks[app]; s != nil {
		return s
	}
	if len(f.socks) >= f.max {
		return nil
	}
	c, err := f.listen(!app.Addr().Is4())
	if err != nil {
		f.log.Debug("direct UDP socket not opened", "err", err)
		return nil
	}
	s := &fwdSock{conn: c, app: app}
	s.onlyDNS.Store(true)
	s.last.Store(time.Now().UnixNano())
	f.socks[app] = s
	go f.read(s)
	return s
}

func (f *udpForwarder) read(s *fwdSock) {
	buf := make([]byte, 65535)
	for {
		n, from, err := s.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			f.remove(s)
			return
		}
		from = netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
		if from.Addr().Is4() != s.app.Addr().Is4() {
			continue
		}
		s.last.Store(time.Now().UnixNano())
		f.Recv.Add(1)
		f.deliver(packet.BuildUDP(from, s.app, buf[:n]))
	}
}

func (f *udpForwarder) remove(s *fwdSock) {
	f.mu.Lock()
	if f.socks[s.app] == s {
		delete(f.socks, s.app)
	}
	f.mu.Unlock()
	s.conn.Close()
}

// sweep closes idle sockets.
func (f *udpForwarder) sweep(now time.Time) {
	f.mu.Lock()
	var idle []*fwdSock
	for _, s := range f.socks {
		limit := f.idle
		if s.onlyDNS.Load() {
			limit = f.dnsIdle
		}
		if now.Sub(time.Unix(0, s.last.Load())) > limit {
			idle = append(idle, s)
		}
	}
	f.mu.Unlock()
	for _, s := range idle {
		f.remove(s)
	}
}

// reset closes every socket: the network changed, a new one binds to the
// new interface.
func (f *udpForwarder) reset() {
	f.mu.Lock()
	socks := f.socks
	f.socks = nil
	f.mu.Unlock()
	for _, s := range socks {
		s.conn.Close()
	}
}

func (f *udpForwarder) close() {
	f.mu.Lock()
	f.closed = true
	f.mu.Unlock()
	f.reset()
}

func (f *udpForwarder) len() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.socks)
}
