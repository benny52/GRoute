//go:build darwin

package attrib

import (
	"net/netip"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// readPCBs reads the kernel's list of TCP or UDP sockets.
func readPCBs(udp bool) ([]PCB, error) {
	name := "net.inet.tcp.pcblist_n"
	if udp {
		name = "net.inet.udp.pcblist_n"
	}
	buf, err := unix.SysctlRaw(name)
	if err != nil {
		return nil, err
	}
	return ParsePCBList(buf), nil
}

// pcbCache shares one read of a list between the lookups that wait for
// it: a read that starts after a lookup asked holds that lookup's socket.
type pcbCache struct {
	mu   sync.Mutex
	at   time.Time
	pcbs []PCB
}

var tcpPCBs, udpPCBs pcbCache

func (c *pcbCache) get(udp bool, asked time.Time) []PCB {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.at.After(asked) {
		return c.pcbs
	}
	start := time.Now()
	p, err := readPCBs(udp)
	if err != nil {
		return nil
	}
	c.pcbs, c.at = p, start
	return p
}

// LookupOwner finds the process of a socket on macOS (Core.OwnerFallback).
func LookupOwner(proto uint8, local, remote netip.AddrPort) (uint32, bool) {
	asked := time.Now()
	if proto == 17 {
		return MatchUDP(udpPCBs.get(true, asked), local, remote)
	}
	return MatchTCP(tcpPCBs.get(false, asked), local, remote)
}
