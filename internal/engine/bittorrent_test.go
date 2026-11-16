package engine

import (
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/engine/nat"
	"github.com/lardan099/hyroute/internal/packet"
	"github.com/lardan099/hyroute/internal/rules"
)

func TestBitTorrentRoutesBothModes(t *testing.T) {
	for _, def := range []rules.Action{rules.Direct, rules.Tunnel} {
		t.Run(def.String(), func(t *testing.T) {
			cfg := rules.Config{DefaultAction: def, Rules: []rules.Rule{
				{Name: "BitTorrent", Protocol: "bittorrent", Action: rules.Direct},
				{Name: "Selected app", Apps: []rules.AppMatch{{Pattern: "curl.exe"}}, Action: rules.Tunnel},
			}}
			h := newHarness(t, cfg, Options{})
			h.own(6, L, R, 100)
			h.sendTCP(L, R, packet.FlagSYN, "")
			h.next(t)
			e := h.c.NAT.LookupFlow(flowKey(L, R))
			if e == nil || e.Mode != nat.Sniff {
				t.Fatal("TCP connected before inspecting handshake")
			}
			if res := h.c.RelayDecide(e, "", rules.SrcNone, true); res.Action != rules.Direct || res.Rule != "BitTorrent" {
				t.Fatalf("peer: %+v", res)
			}
			if res := h.c.RelayDecide(e, "", rules.SrcNone, false); res.Action != rules.Tunnel || res.Rule != "Selected app" {
				t.Fatalf("encrypted or ordinary traffic: %+v", res)
			}
			h.own(17, L, R, 100)
			syn := make([]byte, 20)
			syn[0] = 0x41
			h.sendUDP(L, R, syn)
			h.next(t)
			uf := h.c.udp[flowKey(L, R)]
			if uf == nil || uf.route != rules.Direct || uf.rec.View(time.Now()).Rule != "BitTorrent" {
				t.Fatal("uTP did not go direct")
			}
			h.sendUDP(L, R, []byte("next datagram"))
			h.next(t)
		})
	}
}

func TestBitTorrentEarlierApplicationWins(t *testing.T) {
	cfg := rules.Config{DefaultAction: rules.Tunnel, Rules: []rules.Rule{
		{Name: "Browser policy", Apps: []rules.AppMatch{{Pattern: "chrome.exe"}}, Action: rules.Tunnel},
		{Name: "BitTorrent", Protocol: "bittorrent", Action: rules.Direct},
		{Name: "My torrent client", Apps: []rules.AppMatch{{Pattern: "curl.exe"}}, Action: rules.Direct},
	}}
	h := newHarness(t, cfg, Options{})
	h.own(6, L, R, 200)
	h.sendTCP(L, R, packet.FlagSYN, "")
	h.next(t)
	if e := h.c.NAT.LookupFlow(flowKey(L, R)); e == nil || e.Mode != nat.NoSniff {
		t.Fatal("program rule above torrent rule must win at SYN")
	}
	h.own(17, L, R, 100)
	h.sendUDP(L, R, []byte("opaque encrypted data"))
	h.next(t)
	if v := h.c.udp[flowKey(L, R)].rec.View(time.Now()); v.Rule != "My torrent client" || v.BitTorrent {
		t.Fatalf("optional program %v", v)
	}
}

func TestBitTorrentSYNPolicy(t *testing.T) {
	torrent := rules.Rule{Name: "torrent", Protocol: "bittorrent", Action: rules.Direct}
	t.Run("already direct", func(t *testing.T) {
		h := newHarness(t, rules.Config{DefaultAction: rules.Direct, Rules: []rules.Rule{torrent}}, Options{})
		h.own(6, L, R, 100)
		h.sendTCP(L, R, packet.FlagSYN, "")
		actual := h.next(t)
		if !actual.addr.Outbound() || h.c.NAT.LookupFlow(flowKey(L, R)) != nil {
			t.Fatal("all-direct connection relayed unnecessarily")
		}
	})
	t.Run("IPv4 fallback", func(t *testing.T) {
		h := newHarness(t, rules.Config{DefaultAction: rules.Tunnel, Rules: []rules.Rule{torrent}}, Options{BlockIPv6Tunnel: true})
		h.own(6, L6, R6, 100)
		h.sendTCP(L6, R6, packet.FlagSYN, "")
		actual := h.next(t)
		if actual.pkt.TCPFlags()&packet.FlagRST == 0 {
			t.Fatal("expected an IPv6 reset at SYN while IPv4 is available")
		}
	})
	t.Run("IPv6 only", func(t *testing.T) {
		h := newHarness(t, rules.Config{DefaultAction: rules.Tunnel, Rules: []rules.Rule{torrent}}, Options{BlockIPv6Tunnel: true})
		h.c.IPv4Route = func() bool { return false }
		h.own(6, L6, R6, 100)
		h.sendTCP(L6, R6, packet.FlagSYN, "")
		h.next(t)
		e := h.c.NAT.LookupFlow(flowKey(L6, R6))
		if e == nil || e.Mode != nat.Sniff || h.c.RelayDecide(e, "", rules.SrcNone, true).Action != rules.Direct {
			t.Fatal("IPv6-only direct peer was blocked")
		}
	})
}
