//go:build darwin

package attrib

import (
	"net"
	"net/netip"
	"os"
	"testing"
)

// The kernel's own list names this process as the owner of its sockets:
// the layout ParsePCBList reads matches this macOS.
func TestLookupOwnerSelf(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	local := c.LocalAddr().(*net.TCPAddr).AddrPort()
	remote := c.RemoteAddr().(*net.TCPAddr).AddrPort()
	pid, ok := LookupOwner(6, local, remote)
	if !ok || pid != uint32(os.Getpid()) {
		t.Fatalf("tcp %v -> %v: pid %d ok=%v, want %d", local, remote, pid, ok, os.Getpid())
	}
	u, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	ul := u.LocalAddr().(*net.UDPAddr).AddrPort()
	pid, ok = LookupOwner(17, ul, netip.MustParseAddrPort("127.0.0.1:9"))
	if !ok || pid != uint32(os.Getpid()) {
		t.Fatalf("udp %v: pid %d ok=%v", ul, pid, ok)
	}
	u6, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Skip("no IPv6:", err)
	}
	defer u6.Close()
	ul6 := u6.LocalAddr().(*net.UDPAddr).AddrPort()
	if pid, ok = LookupOwner(17, ul6, netip.MustParseAddrPort("[::1]:9")); !ok || pid != uint32(os.Getpid()) {
		t.Fatalf("udp6 %v: pid %d ok=%v", ul6, pid, ok)
	}
}
