//go:build darwin

package engine

import (
	"encoding/binary"
	"net/netip"
	"sync"

	"golang.org/x/sys/unix"
)

// icmpForwarder sends the applications' pings (ICMP echo) to the network
// from a socket on the physical interface, as the forwarder does UDP, and
// writes the replies into the device. Pings are not routed: on Windows
// the engine never captures ICMP either.
type icmpForwarder struct {
	e *Engine

	mu    sync.Mutex
	socks [2]*icmpSock // IPv4, IPv6
}

type icmpSock struct {
	fd     int
	idx    int // the interface it is bound to
	v6     bool
	closed chan struct{}
	once   sync.Once
}

const (
	protoICMP   = 1
	protoICMPv6 = 58
)

// handle takes an ICMP or ICMPv6 packet from the device; false: not one.
func (f *icmpForwarder) handle(pkt []byte) bool {
	if len(pkt) < 1 {
		return false
	}
	switch pkt[0] >> 4 {
	case 4:
		if len(pkt) < 20 || pkt[9] != protoICMP {
			return false
		}
		ihl := int(pkt[0]&0xf) * 4
		total := int(binary.BigEndian.Uint16(pkt[2:]))
		if ihl < 20 || total > len(pkt) || total < ihl+8 || binary.BigEndian.Uint16(pkt[6:])&0x3fff != 0 {
			return true // a fragment or broken: dropped
		}
		msg := pkt[ihl:total]
		if msg[0] == 8 { // echo request
			f.send(false, netip.AddrFrom4([4]byte(pkt[16:20])), msg)
		}
		return true
	case 6:
		if len(pkt) < 48 || pkt[6] != protoICMPv6 {
			return false
		}
		msg := pkt[40:]
		if l := int(binary.BigEndian.Uint16(pkt[4:])); l <= len(msg) {
			msg = msg[:l]
		}
		if len(msg) >= 8 && msg[0] == 128 { // echo request
			f.send(true, netip.AddrFrom16([16]byte(pkt[24:40])), msg)
		}
		return true
	}
	return false
}

func (f *icmpForwarder) send(v6 bool, dst netip.Addr, msg []byte) {
	s := f.sock(v6)
	if s == nil {
		return
	}
	var sa unix.Sockaddr
	if v6 {
		sa = &unix.SockaddrInet6{Addr: dst.As16()}
	} else {
		sa = &unix.SockaddrInet4{Addr: dst.As4()}
	}
	if err := unix.Sendto(s.fd, msg, 0, sa); err != nil {
		f.e.log.Debug("ping not sent", "dst", dst, "err", err)
	}
}

// sock is the socket for the family, on the current physical interface.
func (f *icmpForwarder) sock(v6 bool) *icmpSock {
	idx := int(f.e.bound4.Load())
	fam, proto, i := unix.AF_INET, protoICMP, 0
	if v6 {
		idx = int(f.e.bound6.Load())
		fam, proto, i = unix.AF_INET6, protoICMPv6, 1
	}
	if idx == 0 {
		return nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if s := f.socks[i]; s != nil {
		if s.idx == idx {
			return s
		}
		s.close() // the network changed
		f.socks[i] = nil
	}
	fd, err := unix.Socket(fam, unix.SOCK_DGRAM, proto)
	if err != nil {
		f.e.log.Debug("ping socket not opened", "err", err)
		return nil
	}
	unix.CloseOnExec(fd)
	if v6 {
		err = unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF, idx)
	} else {
		err = unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_BOUND_IF, idx)
	}
	if err == nil {
		// A read wakes up every second to see the socket closed.
		err = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 1})
	}
	if err != nil {
		unix.Close(fd)
		return nil
	}
	s := &icmpSock{fd: fd, idx: idx, v6: v6, closed: make(chan struct{})}
	f.socks[i] = s
	go f.read(s)
	return s
}

func (s *icmpSock) close() { s.once.Do(func() { close(s.closed) }) }

func (f *icmpForwarder) read(s *icmpSock) {
	defer unix.Close(s.fd)
	buf := make([]byte, 65535)
	for {
		select {
		case <-s.closed:
			return
		default:
		}
		n, from, err := unix.Recvfrom(s.fd, buf, 0)
		if err != nil {
			if err == unix.EAGAIN || err == unix.EINTR {
				continue
			}
			return
		}
		msg := buf[:n]
		if s.v6 {
			sa, ok := from.(*unix.SockaddrInet6)
			if !ok || len(msg) < 8 || msg[0] != 129 { // echo reply
				continue
			}
			f.e.deliver(buildICMPv6(netip.AddrFrom16(sa.Addr), tunAddr6, msg))
			continue
		}
		// An IPv4 ICMP datagram socket reads the IP header too.
		if len(msg) >= 20 && msg[0]>>4 == 4 {
			msg = msg[int(msg[0]&0xf)*4:]
		}
		sa, ok := from.(*unix.SockaddrInet4)
		if !ok || len(msg) < 8 || msg[0] != 0 { // echo reply
			continue
		}
		f.e.deliver(buildICMPv4(netip.AddrFrom4(sa.Addr), tunAddr4, msg))
	}
}

func (f *icmpForwarder) close() {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i, s := range f.socks {
		if s != nil {
			s.close()
			f.socks[i] = nil
		}
	}
}

// buildICMPv4 wraps an ICMP message in an IPv4 header (the message keeps
// its checksum: it does not cover the header).
func buildICMPv4(src, dst netip.Addr, msg []byte) []byte {
	b := make([]byte, 20+len(msg))
	b[0], b[8], b[9] = 0x45, 64, protoICMP
	binary.BigEndian.PutUint16(b[2:], uint16(len(b)))
	s4, d4 := src.As4(), dst.As4()
	copy(b[12:], s4[:])
	copy(b[16:], d4[:])
	binary.BigEndian.PutUint16(b[10:], ^fold16(sum16(b[:20], 0)))
	copy(b[20:], msg)
	return b
}

// buildICMPv6 wraps an ICMPv6 message in an IPv6 header; its checksum
// covers the pseudo-header, so it is computed for these addresses.
func buildICMPv6(src, dst netip.Addr, msg []byte) []byte {
	b := make([]byte, 40+len(msg))
	b[0], b[6], b[7] = 0x60, protoICMPv6, 64
	binary.BigEndian.PutUint16(b[4:], uint16(len(msg)))
	s16, d16 := src.As16(), dst.As16()
	copy(b[8:], s16[:])
	copy(b[24:], d16[:])
	m := b[40:]
	copy(m, msg)
	m[2], m[3] = 0, 0
	var pseudo [40]byte
	copy(pseudo[0:], s16[:])
	copy(pseudo[16:], d16[:])
	binary.BigEndian.PutUint32(pseudo[32:], uint32(len(msg)))
	pseudo[39] = protoICMPv6
	binary.BigEndian.PutUint16(m[2:], ^fold16(sum16(m, sum16(pseudo[:], 0))))
	return b
}

func sum16(b []byte, s uint32) uint32 {
	for len(b) >= 2 {
		s += uint32(b[0])<<8 | uint32(b[1])
		b = b[2:]
	}
	if len(b) == 1 {
		s += uint32(b[0]) << 8
	}
	return s
}

func fold16(s uint32) uint16 {
	for s>>16 != 0 {
		s = s&0xffff + s>>16
	}
	return uint16(s)
}
