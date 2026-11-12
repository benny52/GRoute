package engine

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"
	"unsafe"

	"github.com/lardan099/hyroute/internal/divert"
	"github.com/lardan099/hyroute/internal/packet"
	"github.com/lardan099/hyroute/internal/rules"
)

// Artificial packets use the same Core path as the WinDivert H1 handle.
// No route, adapter, driver or VPN is opened.
func TestWizardLocalNetworks(t *testing.T) {
	for _, tc := range []struct {
		name, destination string
		action            rules.Action
		managed, tunnel   bool
	}{
		{"home LAN", "192.168.1.88:445", rules.Direct, true, false},
		{"office OpenVPN", "10.8.0.9:445", rules.Direct, true, false},
		{"office explicitly through GRoute", "10.8.0.9:445", rules.Tunnel, true, true},
		{"private network outside chosen prefixes", "172.18.1.3:445", rules.Tunnel, true, false},
		{"earlier configuration", "10.8.0.9:445", rules.Tunnel, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rule := rules.Rule{Name: "LAN", LocalNetworks: tc.managed, Domains: []string{"192.168.1.0/24", "10.8.0.0/16"}, Action: tc.action}
			h := newHarness(t, rules.Config{Rules: []rules.Rule{rule}, DefaultAction: rules.Tunnel}, Options{})
			h.own(6, L, tc.destination, 100)
			// Simulate the adapter selected by Windows. At the network layer
			// the first two UINT32s of the WINDIVERT_ADDRESS union (offset 16)
			// are IfIdx and SubIfIdx.
			addr := outAddr()
			raw := (*[divert.AddressSize]byte)(unsafe.Pointer(addr))
			ifIndex := uint32(7)
			if tc.destination == "10.8.0.9:445" {
				ifIndex = 23
			}
			binary.LittleEndian.PutUint32(raw[16:], ifIndex)
			binary.LittleEndian.PutUint32(raw[20:], 1)
			p := packet.BuildTCP(netip.MustParseAddrPort(L), netip.MustParseAddrPort(tc.destination), packet.FlagSYN, 1000, 0, nil)
			original := bytes.Clone(p)
			h.c.HandlePacket(p, addr)
			got := h.next(t)
			if tc.tunnel {
				if got.addr.Outbound() || got.pkt.DstPort() != relayPort {
					t.Fatalf("expected relay, got %v", got.pkt.Dst())
				}
			} else if !got.addr.Outbound() || got.addr.IfIdx() != ifIndex || got.addr.SubIfIdx() != 1 || !bytes.Equal(got.pkt.Buf, original) {
				t.Fatalf("changed direct packet %v -> %v via adapter %d", got.pkt.Src(), got.pkt.Dst(), got.addr.IfIdx())
			}
		})
	}
}

func TestPrivatePolicyHotSwapNoServer(t *testing.T) {
	const dst = "10.2.0.99:443"
	h := newHarness(t, rules.Config{DefaultAction: rules.Direct}, Options{})
	h.tun.up.Store(false)
	for i, way := range []rules.Action{rules.Direct, rules.Tunnel, rules.Direct} {
		cfg := rules.Config{DefaultAction: rules.Tunnel, Rules: []rules.Rule{{LocalNetworks: true, Domains: []string{"10.0.0.0/8"}, Action: way}}}
		set, err := rules.Compile(cfg)
		if err != nil {
			t.Fatal(err)
		}
		h.c.Rules.Swap(set)
		src := netip.AddrPortFrom(netip.MustParseAddr("10.2.0.20"), uint16(51000+i)).String()
		h.own(6, src, dst, 100)
		h.sendTCP(src, dst, packet.FlagSYN, "")
		got := h.next(t)
		if way == rules.Tunnel {
			if got.addr.Outbound() || got.pkt.TCPFlags()&packet.FlagRST == 0 {
				t.Fatal("private SYN escaped with no available server")
			}
		} else if !got.addr.Outbound() || got.pkt.Dst() != netip.MustParseAddrPort(dst) {
			t.Fatal("private DIRECT lost its route")
		}
	}
}

func TestExistingPrivateUDPDoesNotLeakOnRulesetChange(t *testing.T) {
	const dst = "10.8.0.9:9040"
	rule := rules.Rule{LocalNetworks: true, Domains: []string{"10.0.0.0/8"}, Action: rules.Block}
	h := newHarness(t, rules.Config{Rules: []rules.Rule{rule}, DefaultAction: rules.Direct}, Options{})
	h.own(17, L, dst, 100)
	h.sendUDP(L, dst, []byte("existing"))
	h.none(t)
	next, err := rules.Compile(rules.Config{DefaultAction: rules.Direct})
	if err != nil {
		t.Fatal(err)
	}
	h.c.Rules.Swap(next)
	h.sendUDP(L, dst, []byte("existing"))
	h.none(t)
	parts := fragments4(L, dst, 3100, 17)
	for _, i := range []int{1, 0, 2} {
		h.c.HandlePacket(parts[i], outAddr())
	}
	if n := h.fragCount(); n != 0 {
		t.Fatalf("leaked %d fragments of an existing blocked flow", n)
	}
	h.sendUDP("192.168.1.5:40001", dst, []byte("new"))
	got := h.next(t)
	if !got.addr.Outbound() {
		t.Fatal("new datagram did not follow the current direct route")
	}
}

func TestPrivateDirectMiddleFragmentPassesImmediately(t *testing.T) {
	h := newHarness(t, rules.Config{DefaultAction: rules.Tunnel, Rules: []rules.Rule{
		{LocalNetworks: true, Action: rules.Tunnel, Domains: []string{"10.8.0.0/16"}},
	}}, Options{})
	parts := fragments4(L, "192.168.1.88:445", 3100, 18)
	for _, i := range []int{1, 0, 2} {
		h.c.HandlePacket(parts[i], outAddr())
		select {
		case got := <-h.frags:
			if !bytes.Equal(got, parts[i]) {
				t.Fatal("rewrote direct fragment")
			}
		default:
			t.Fatalf("held direct fragment %d", i)
		}
	}
}
