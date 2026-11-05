//go:build darwin

package netwatch

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"

	"github.com/lardan099/hyroute/internal/netmode"
)

// Watcher reads the network the Mac is on: the interface and the router
// of the default route, the interface's hardware port and, when macOS
// gives it, the Wi-Fi name. The network's identity («Именно эта сеть») is
// its router (macNetID). Nothing is sent on the network: the router's MAC
// comes from the ARP table.
type Watcher struct{}

// New makes a Watcher.
func New() *Watcher { return &Watcher{} }

// Snapshot reads the active network (macOS has no names or categories of
// networks: Name is the Wi-Fi name or the port's name, Category is empty).
func (w *Watcher) Snapshot(wantSSID bool) (netmode.Snapshot, error) {
	var snap netmode.Snapshot
	ifName, gw := defaultRoute(syscall.AF_INET)
	if ifName == "" {
		ifName, gw = defaultRoute(syscall.AF_INET6)
	}
	if ifName == "" {
		return snap, nil
	}
	port, ok := hardwarePorts()[ifName]
	if !ok {
		port = macPort{Name: ifName, Kind: netmode.Other}
	}
	n := netmode.Network{Adapter: port.Kind, AdapterName: port.Name, AdapterID: ifName, Name: port.Name}
	if gw.IsValid() {
		n.GatewayIP = gw.String()
		if gw.Is4() {
			if out, err := exec.Command("/usr/sbin/arp", "-n", gw.String()).Output(); err == nil {
				n.GatewayMAC = parseARP(string(out))
			}
		}
	}
	if n.GatewayIP != "" {
		// macOS names no networks: the router's address tells one from
		// another in the list (the Wi-Fi name replaces it when known).
		n.Name = port.Name + " · " + n.GatewayIP
	}
	n.ID = macNetID(n.GatewayMAC)
	n.Identified = n.ID != ""
	if wantSSID && n.Adapter == netmode.WiFi {
		switch s, err := w.SSID(ifName); {
		case err == netmode.ErrSSIDDenied:
			n.SSIDDenied = true
		case err != nil:
			snap.Err = "имя Wi-Fi: " + err.Error()
		case s != "":
			n.SSID, n.Name = s, s
		}
	}
	snap.Active = &n
	return snap, nil
}

// SSID of an interface ("" + nil when it is not on Wi-Fi);
// netmode.ErrSSIDDenied when macOS hides it.
func (w *Watcher) SSID(adapterID string) (string, error) {
	if adapterID == "" || strings.ContainsAny(adapterID, " /") {
		return "", nil
	}
	out, err := exec.Command("/usr/sbin/ipconfig", "getsummary", adapterID).Output()
	if err != nil {
		return "", err
	}
	return parseSummarySSID(string(out))
}

func hardwarePorts() map[string]macPort {
	out, err := exec.Command("/usr/sbin/networksetup", "-listallhardwareports").Output()
	if err != nil {
		return nil
	}
	return parseHardwarePorts(string(out))
}

const rtfIfScope = 0x1000000 // RTF_IFSCOPE

// defaultRoute is the unscoped default route of the family that is not
// another VPN's interface route; HyRoute's own routes (0/1, 128/1) are not
// default routes.
func defaultRoute(af int) (string, netip.Addr) {
	rib, err := route.FetchRIB(af, route.RIBTypeRoute, 0)
	if err != nil {
		return "", netip.Addr{}
	}
	msgs, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		return "", netip.Addr{}
	}
	for _, m := range msgs {
		rm, ok := m.(*route.RouteMessage)
		if !ok || rm.Flags&unix.RTF_UP == 0 || rm.Flags&rtfIfScope != 0 || len(rm.Addrs) <= unix.RTAX_NETMASK {
			continue
		}
		if !zero(rm.Addrs[unix.RTAX_DST]) || !zero(rm.Addrs[unix.RTAX_NETMASK]) {
			continue
		}
		var gw netip.Addr
		switch g := rm.Addrs[unix.RTAX_GATEWAY].(type) {
		case *route.Inet4Addr:
			gw = netip.AddrFrom4(g.IP)
		case *route.Inet6Addr:
			gw = netip.AddrFrom16(g.IP)
		}
		i, err := net.InterfaceByIndex(rm.Index)
		if err != nil || strings.HasPrefix(i.Name, "utun") && !gw.IsValid() {
			continue
		}
		return i.Name, gw
	}
	return "", netip.Addr{}
}

func zero(a route.Addr) bool {
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

// Watch reports interface, address and route changes from the routing
// socket, coalesced (a burst gives one event half a second after it ends)
// into a 1-buffered channel, until ctx ends.
func (w *Watcher) Watch(ctx context.Context) (<-chan struct{}, error) {
	fd, err := unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW, unix.AF_UNSPEC)
	if err != nil {
		return nil, err
	}
	ch := make(chan struct{}, 1)
	raw := make(chan struct{}, 1)
	go func() {
		<-ctx.Done()
		unix.Close(fd) // ends the read
	}()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, err := unix.Read(fd, buf)
			if err != nil {
				if err == unix.EINTR {
					continue
				}
				close(raw)
				return
			}
			if interesting(buf[:n]) {
				select {
				case raw <- struct{}{}:
				default:
				}
			}
		}
	}()
	go func() {
		const quiet = 500 * time.Millisecond
		t := time.NewTimer(time.Hour)
		t.Stop()
		for {
			select {
			case _, ok := <-raw:
				if !ok {
					return
				}
				t.Reset(quiet)
			case <-t.C:
				select {
				case ch <- struct{}{}:
				default:
				}
			case <-ctx.Done():
				return
			}
		}
	}()
	return ch, nil
}

// interesting: a message a network change sends. Host routes are not:
// macOS clones one for each destination it talks to and ARP adds its
// entries as routes, so they come with all traffic.
func interesting(msg []byte) bool {
	// rt_msghdr: msglen u16, version u8, type u8, index u16, (pad), flags
	// i32 at 8; if_msghdr and ifa_msghdr share the first four bytes.
	if len(msg) < 4 {
		return false
	}
	switch msg[3] {
	case unix.RTM_IFINFO, unix.RTM_NEWADDR, unix.RTM_DELADDR:
		return true
	case unix.RTM_ADD, unix.RTM_DELETE, unix.RTM_CHANGE:
		if len(msg) < 12 {
			return false
		}
		flags := int(binary.LittleEndian.Uint32(msg[8:12]))
		return flags&(unix.RTF_HOST|unix.RTF_WASCLONED|unix.RTF_LLINFO) == 0
	}
	return false
}
