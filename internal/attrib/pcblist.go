package attrib

import (
	"encoding/binary"
	"net/netip"
)

// macOS: the kernel's socket list (sysctl net.inet.tcp.pcblist_n and
// net.inet.udp.pcblist_n, what netstat reads). The buffer is a struct
// xinpgen, then per socket a run of items (struct xinpcb_n, xsocket_n,
// two xsockbuf_n, xsockstat_n and for TCP xtcpcb_n), each starting with its
// length and kind and padded to 8 bytes, then a closing xinpgen. The layouts
// are private to the kernel; only fields whose place is checked are read
// (see socketPID).

// PCB is one socket of the list.
type PCB struct {
	Local, Remote netip.AddrPort
	// PID is the process the socket works for: the effective PID of a
	// socket used on behalf of another process (a system daemon's
	// connection for an application), else the last process to use it.
	PID uint32
}

const (
	xsoSocket = 0x001
	xsoInpcb  = 0x010

	inpIPv4 = 0x1
	inpIPv6 = 0x2
)

// ParsePCBList reads a pcblist_n buffer. Sockets whose owner cannot be
// read are left out.
func ParsePCBList(buf []byte) []PCB {
	if len(buf) < 8 {
		return nil
	}
	hdr := int(binary.LittleEndian.Uint32(buf))
	if hdr < 8 || hdr > len(buf) {
		return nil
	}
	var out []PCB
	var cur *PCB
	have := false
	flush := func() {
		if cur != nil && have {
			out = append(out, *cur)
		}
		cur, have = nil, false
	}
	off := hdr
	// The closing xinpgen has the header's length and ends the buffer.
	for off+8 <= len(buf) && len(buf)-off > hdr {
		n := int(binary.LittleEndian.Uint32(buf[off:]))
		kind := binary.LittleEndian.Uint32(buf[off+4:])
		if n < 8 || off+n > len(buf) {
			break
		}
		item := buf[off : off+n]
		switch kind {
		case xsoInpcb:
			flush()
			if p, ok := parseInpcb(item); ok {
				cur = &p
			}
		case xsoSocket:
			if cur != nil {
				if pid, ok := socketPID(item); ok {
					cur.PID, have = pid, true
				}
			}
		}
		off += (n + 7) &^ 7
	}
	flush()
	return out
}

// parseInpcb reads struct xinpcb_n: ports at 16 and 18 (network order),
// inp_vflag at 28, the foreign address at 32 and the local one at 48 (16
// bytes each; IPv4 in the last four).
func parseInpcb(b []byte) (PCB, bool) {
	if len(b) < 64 {
		return PCB{}, false
	}
	fport := binary.BigEndian.Uint16(b[16:])
	lport := binary.BigEndian.Uint16(b[18:])
	vflag := b[28]
	addr := func(a []byte) netip.Addr {
		if vflag&inpIPv4 != 0 {
			return netip.AddrFrom4([4]byte(a[12:16]))
		}
		return netip.AddrFrom16([16]byte(a[:16])).Unmap()
	}
	if vflag&(inpIPv4|inpIPv6) == 0 {
		return PCB{}, false
	}
	return PCB{
		Remote: netip.AddrPortFrom(addr(b[32:48]), fport),
		Local:  netip.AddrPortFrom(addr(b[48:64]), lport),
	}, true
}

// socketPID reads so_last_pid and so_e_pid of struct xsocket_n. Whether the
// kernel packs it to 4 bytes moves so_pcb (8 bytes, at 28 or 32) and every
// field after it, so the layout is told by the fields that must hold
// known values: xso_protocol (TCP or UDP) and xso_family (AF_INET or
// AF_INET6), at 36 and 40 packed, 40 and 44 aligned; the PIDs follow at 64
// and 68, or 68 and 72.
func socketPID(b []byte) (uint32, bool) {
	valid := func(at int) bool {
		if len(b) < at+8 {
			return false
		}
		proto := binary.LittleEndian.Uint32(b[at:])
		fam := binary.LittleEndian.Uint32(b[at+4:])
		return (proto == 6 || proto == 17) && (fam == 2 || fam == 30)
	}
	var pids int
	switch {
	case valid(36) && len(b) >= 72:
		pids = 64
	case valid(40) && len(b) >= 76:
		pids = 68
	default:
		return 0, false
	}
	last := binary.LittleEndian.Uint32(b[pids:])
	eff := binary.LittleEndian.Uint32(b[pids+4:])
	if int32(eff) > 0 {
		return eff, true
	}
	if int32(last) > 0 {
		return last, true
	}
	return 0, false
}

// MatchTCP finds the owner of the TCP connection local -> remote.
func MatchTCP(pcbs []PCB, local, remote netip.AddrPort) (uint32, bool) {
	local, remote = norm(local), norm(remote)
	for _, p := range pcbs {
		if p.Local.Port() == local.Port() && p.Remote == remote &&
			(p.Local.Addr() == local.Addr() || p.Local.Addr().IsUnspecified()) {
			return p.PID, true
		}
	}
	return 0, false
}

// MatchUDP finds the owner of a UDP datagram from local to remote: a socket
// connected to remote first, then one bound to the port (on the address or
// on any). Two unconnected owners of the port are not guessed between.
func MatchUDP(pcbs []PCB, local, remote netip.AddrPort) (uint32, bool) {
	local, remote = norm(local), norm(remote)
	var pid uint32
	found, ambiguous := false, false
	for _, p := range pcbs {
		if p.Local.Port() != local.Port() {
			continue
		}
		if !p.Local.Addr().IsUnspecified() && p.Local.Addr() != local.Addr() {
			continue
		}
		if p.Remote.Port() != 0 {
			if p.Remote == remote {
				return p.PID, true
			}
			continue
		}
		if found && p.PID != pid {
			ambiguous = true
		}
		pid, found = p.PID, true
	}
	return pid, found && !ambiguous
}
