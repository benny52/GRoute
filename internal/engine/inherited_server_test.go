package engine

import (
	"fmt"
	"testing"

	"github.com/lardan099/hyroute/internal/packet"
	"github.com/lardan099/hyroute/internal/rules"
)

func TestInheritedRouteWaitsForMainServer(t *testing.T) {
	cfg := rules.Config{DefaultAction: rules.Direct, Rules: []rules.Rule{{
		Name: "curl", Apps: []rules.AppMatch{{Pattern: "curl.exe"}}, Action: rules.Tunnel,
	}}}
	h := newHarness(t, cfg, Options{})
	h.c.Tunnels = func(id string) Tunnel {
		if id == "B" {
			return h.tun
		}
		return nil
	}
	h.own(6, L, R, 100)
	h.sendTCP(L, R, packet.FlagSYN, "")
	refused := h.next(t)
	if refused.addr.Outbound() || refused.pkt.TCPFlags()&packet.FlagRST == 0 || lastRecord(t, h.c).Outcome != "rst: tunnel unavailable" {
		t.Fatal("a VPN rule without a main server must refuse the connection")
	}
	h.none(t) // In particular, the original outbound SYN was never injected.

	set, err := rules.Compile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	set.Main = "B"
	h.c.Rules.Swap(set)
	const next = "192.168.1.5:40501"
	h.own(6, next, R, 100)
	h.sendTCP(next, R, packet.FlagSYN, "")
	if p := h.next(t).pkt; p.DstPort() != relayPort {
		t.Fatal("a new connection must use the selected main server")
	}
}

func TestMainSwitchAffectsInheritedConnections(t *testing.T) {
	cfg := rules.Config{DefaultAction: rules.Tunnel, Rules: []rules.Rule{
		{Name: "Inherited", Apps: []rules.AppMatch{{Pattern: "curl.exe"}}, Action: rules.Tunnel},
		{Name: "Pinned", Apps: []rules.AppMatch{{Pattern: "chrome.exe"}}, Action: rules.Tunnel, Profile: "B"},
		{Name: "Local", Apps: []rules.AppMatch{{Pattern: "game.exe"}}, Action: rules.Direct},
	}}
	h := newHarness(t, cfg, Options{NoDefaultExclusions: true})
	h.extra["B"], h.extra["D"] = h.tun, h.tun
	port := 40510
	for _, main := range []string{"B", "D"} {
		set, err := rules.Compile(cfg)
		if err != nil {
			t.Fatal(err)
		}
		set.Main = main
		h.c.Rules.Swap(set)
		for _, tc := range []struct {
			pid     uint32
			profile string
		}{{100, main}, {200, "B"}, {300, main}, {400, ""}} {
			src := fmt.Sprintf("192.168.1.5:%d", port)
			port++
			h.own(6, src, R, tc.pid)
			h.sendTCP(src, R, packet.FlagSYN, "")
			inj := h.next(t)
			if tc.profile == "" {
				if !inj.addr.Outbound() || inj.pkt.DstPort() == relayPort {
					t.Fatal("explicit direct rule did not stay direct")
				}
				continue
			}
			e := h.c.NAT.LookupFlow(flowKey(src, R))
			if inj.pkt.DstPort() != relayPort || e == nil || e.Profile != tc.profile {
				t.Fatalf("main %s, PID %d: want tunnel %s, got %+v", main, tc.pid, tc.profile, e)
			}
		}
	}
}
