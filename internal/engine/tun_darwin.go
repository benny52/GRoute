//go:build darwin

package engine

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

// The TUN device's addresses. Applications get the first one as their
// source; the relay listens on it. 198.18.0.0/15 is reserved for
// benchmarking (RFC 2544), so no network uses it.
var (
	tunAddr4 = netip.MustParseAddr("198.18.0.1")
	tunPeer4 = netip.MustParseAddr("198.18.0.2")
	tunAddr6 = netip.MustParseAddr("fdfe:dcba:9876::1")
)

// tunMTU: large, so applications' TCP to the relay moves in few packets.
// Nothing leaves the machine at this size: TCP is terminated by the relay
// and UDP is sent again from a socket.
const tunMTU = 9000

// tunDevice is a utun interface. Every packet read or written starts with
// the address family (4 bytes, network order).
type tunDevice struct {
	f    *os.File
	name string
	v6   bool // the IPv6 address was assigned

	wmu  sync.Mutex
	wbuf []byte
}

const utunControl = "com.apple.net.utun_control"

// openTUN creates a utun interface and assigns its addresses.
func openTUN() (*tunDevice, error) {
	fd, err := unix.Socket(unix.AF_SYSTEM, unix.SOCK_DGRAM, unix.AF_SYS_CONTROL)
	if err != nil {
		return nil, fmt.Errorf("utun: %w", err)
	}
	info := &unix.CtlInfo{}
	copy(info.Name[:], utunControl)
	if err := unix.IoctlCtlInfo(fd, info); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("utun: %w", err)
	}
	// Unit 0: the kernel picks the first free utunN.
	if err := unix.Connect(fd, &unix.SockaddrCtl{ID: info.Id, Unit: 0}); err != nil {
		unix.Close(fd)
		if errors.Is(err, unix.EPERM) {
			return nil, errors.New("utun: нужны права администратора (HyRoute работает через свою службу)")
		}
		return nil, fmt.Errorf("utun: %w", err)
	}
	name, err := unix.GetsockoptString(fd, 2 /* SYSPROTO_CONTROL */, 2 /* UTUN_OPT_IFNAME */)
	if err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("utun name: %w", err)
	}
	unix.CloseOnExec(fd)
	if err := unix.SetNonblock(fd, true); err != nil {
		unix.Close(fd)
		return nil, err
	}
	t := &tunDevice{f: os.NewFile(uintptr(fd), name), name: strings.TrimRight(name, "\x00")}
	if err := run("/sbin/ifconfig", t.name, "inet", tunAddr4.String(), tunPeer4.String(),
		"netmask", "255.255.255.252", "mtu", fmt.Sprint(tunMTU), "up"); err != nil {
		t.close()
		return nil, err
	}
	// IPv6 is optional: without it the routes leave IPv6 alone.
	if err := run("/sbin/ifconfig", t.name, "inet6", tunAddr6.String(), "prefixlen", "126"); err == nil {
		t.v6 = true
	}
	return t, nil
}

func (t *tunDevice) index() int {
	if i, err := net.InterfaceByName(t.name); err == nil {
		return i.Index
	}
	return 0
}

// read returns one packet (without the family header) in buf[4:n].
func (t *tunDevice) read(buf []byte) (int, error) {
	return t.f.Read(buf)
}

func (t *tunDevice) write(pkt []byte) error {
	if len(pkt) == 0 {
		return nil
	}
	fam := uint32(unix.AF_INET)
	if pkt[0]>>4 == 6 {
		fam = unix.AF_INET6
	}
	t.wmu.Lock()
	defer t.wmu.Unlock()
	t.wbuf = append(t.wbuf[:0], 0, 0, 0, 0)
	binary.BigEndian.PutUint32(t.wbuf, fam)
	t.wbuf = append(t.wbuf, pkt...)
	_, err := t.f.Write(t.wbuf)
	return err
}

// close destroys the interface; its routes go with it.
func (t *tunDevice) close() error { return t.f.Close() }

func run(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// defaultRoute is the system's own default route: the interface and the
// gateway the physical network uses.
type defaultRoute struct {
	Index   int
	Name    string
	Gateway netip.Addr // invalid: an interface route (a point-to-point link)
}

// readDefaults finds the unscoped default routes (IPv4, IPv6) that do not
// go through skip (our utun).
func readDefaults(skip int) (v4, v6 defaultRoute) {
	v4 = findDefault(syscall.AF_INET, skip)
	v6 = findDefault(syscall.AF_INET6, skip)
	return
}

const rtfIfScope = 0x1000000 // RTF_IFSCOPE

func findDefault(af int, skip int) defaultRoute {
	rib, err := route.FetchRIB(af, route.RIBTypeRoute, 0)
	if err != nil {
		return defaultRoute{}
	}
	msgs, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		return defaultRoute{}
	}
	for _, m := range msgs {
		rm, ok := m.(*route.RouteMessage)
		if !ok || rm.Flags&unix.RTF_UP == 0 || rm.Flags&rtfIfScope != 0 || rm.Index == skip || len(rm.Addrs) <= unix.RTAX_NETMASK {
			continue
		}
		if !zeroAddr(rm.Addrs[unix.RTAX_DST]) || !zeroAddr(rm.Addrs[unix.RTAX_NETMASK]) {
			continue
		}
		d := defaultRoute{Index: rm.Index}
		switch g := rm.Addrs[unix.RTAX_GATEWAY].(type) {
		case *route.Inet4Addr:
			d.Gateway = netip.AddrFrom4(g.IP)
		case *route.Inet6Addr:
			d.Gateway = netip.AddrFrom16(g.IP)
		}
		if i, err := net.InterfaceByIndex(rm.Index); err == nil {
			d.Name = i.Name
		}
		if d.Name == "" || strings.HasPrefix(d.Name, "utun") && rm.Flags&unix.RTF_GATEWAY == 0 && !d.Gateway.IsValid() {
			// Another VPN's interface route: not a physical network.
			continue
		}
		return d
	}
	return defaultRoute{}
}

// zeroAddr: a default route's destination or mask (absent counts as zero).
func zeroAddr(a route.Addr) bool {
	switch a := a.(type) {
	case nil:
		return true
	case *route.Inet4Addr:
		return a.IP == [4]byte{}
	case *route.Inet6Addr:
		return a.IP == [16]byte{}
	}
	return false
}
