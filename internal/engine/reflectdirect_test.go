package engine

import (
	"net/netip"
	"testing"

	"github.com/lardan099/hyroute/internal/engine/nat"
	"github.com/lardan099/hyroute/internal/packet"
)

// A TUN engine (ReflectDirect) sends Direct TCP through the relay: nothing
// it read may go back out unchanged.
func TestReflectDirectTCP(t *testing.T) {
	h := newHarness(t, appRules, Options{ReflectDirect: true})
	h.c.DNS.AddResponse(dnsResponse(t, "example.org.", "93.184.216.34"))
	h.own(6, L, R, 200)
	h.sendTCP(L, R, packet.FlagSYN, "")
	i := h.next(t)
	if i.addr.Outbound() || i.pkt.Dst() != netip.MustParseAddrPort("192.168.1.5:50123") {
		t.Fatalf("direct SYN not reflected: %v -> %v outbound=%v", i.pkt.Src(), i.pkt.Dst(), i.addr.Outbound())
	}
	e := h.c.NAT.LookupReflect(netip.MustParseAddr("93.184.216.34"), 40000)
	if e == nil || e.Mode != nat.Direct || e.Rec == nil {
		t.Fatalf("entry %+v", e)
	}
	v := lastRecord(t, h.c)
	if v.Route != "direct" || v.Outcome != "reflected: direct" || h.c.Passed.Load() != 1 {
		t.Fatalf("%+v", v)
	}
	// The relay's answer goes back to the application.
	h.sendTCP("192.168.1.5:50123", "93.184.216.34:40000", packet.FlagSYN|packet.FlagACK, "")
	if i := h.next(t); i.addr.Outbound() || i.pkt.Src() != netip.MustParseAddrPort(R) {
		t.Fatalf("reply %v -> %v", i.pkt.Src(), i.pkt.Dst())
	}
}

// An excluded address the routes still send into the device goes through
// the relay too, without a record; a segment of a connection the engine
// never saw is reset.
func TestReflectDirectExcludedAndUntracked(t *testing.T) {
	h := newHarness(t, appRules, Options{ReflectDirect: true})
	const lan = "10.0.0.7:22"
	h.sendTCP(L, lan, packet.FlagSYN, "")
	if i := h.next(t); i.addr.Outbound() || i.pkt.DstPort() != relayPort {
		t.Fatalf("excluded SYN: %v -> %v", i.pkt.Src(), i.pkt.Dst())
	}
	if e := h.c.NAT.LookupReflect(netip.MustParseAddr("10.0.0.7"), 40000); e == nil || e.Mode != nat.Direct || e.Rec != nil {
		t.Fatalf("entry %+v", e)
	}
	h.sendTCP(L, lan, packet.FlagACK, "x")
	if i := h.next(t); i.pkt.DstPort() != relayPort {
		t.Fatal("excluded data not reflected")
	}
	// Untracked: reset, also on the next segment, never passed.
	h.sendTCP("192.168.1.5:40001", R, packet.FlagACK, "old")
	for range 2 {
		i := h.next(t)
		if i.addr.Outbound() || i.pkt.TCPFlags()&packet.FlagRST == 0 {
			t.Fatalf("untracked: %v -> %v flags %x", i.pkt.Src(), i.pkt.Dst(), i.pkt.TCPFlags())
		}
		h.sendTCP("192.168.1.5:40001", R, packet.FlagACK, "old")
	}
	h.next(t)
	// Its RST is dropped, not answered.
	h.sendTCP("192.168.1.5:40002", R, packet.FlagRST, "")
	h.none(t)
}
