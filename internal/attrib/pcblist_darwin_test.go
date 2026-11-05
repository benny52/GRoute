//go:build darwin

package attrib

import (
	"encoding/binary"
	"net"
	"net/netip"
	"os"
	"testing"

	"golang.org/x/sys/unix"
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
		dumpPCBs(t, false, local.Port())
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
		dumpPCBs(t, true, ul.Port())
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

// dumpPCBs logs the items of the raw list around the socket with port, to
// read the kernel's layout from a failing run.
func dumpPCBs(t *testing.T, udp bool, port uint16) {
	name := "net.inet.tcp.pcblist_n"
	if udp {
		name = "net.inet.udp.pcblist_n"
	}
	buf, err := unix.SysctlRaw(name)
	if err != nil {
		t.Log(err)
		return
	}
	t.Logf("%s: %d bytes, header %x", name, len(buf), buf[:min(32, len(buf))])
	off := int(binary.LittleEndian.Uint32(buf))
	var group [][]byte
	for off+8 <= len(buf) {
		n := int(binary.LittleEndian.Uint32(buf[off:]))
		kind := binary.LittleEndian.Uint32(buf[off+4:])
		if n < 8 || off+n > len(buf) {
			break
		}
		item := buf[off : off+n]
		if kind == xsoInpcb {
			for _, it := range group {
				if len(it) >= 20 && binary.LittleEndian.Uint32(it[4:]) == xsoInpcb && (binary.BigEndian.Uint16(it[18:]) == port || binary.BigEndian.Uint16(it[16:]) == port) {
					for _, x := range group {
						t.Logf("kind %#x len %d: %x", binary.LittleEndian.Uint32(x[4:]), len(x), x)
					}
				}
			}
			group = nil
		}
		group = append(group, item)
		off += (n + 7) &^ 7
	}
	t.Logf("parsed: %+v", ParsePCBList(buf))
}
