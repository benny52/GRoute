package app

import (
	"slices"
	"testing"

	"github.com/lardan099/hyroute/internal/groups"
	"github.com/lardan099/hyroute/internal/rules"
	"github.com/lardan099/hyroute/internal/store"
	"github.com/lardan099/hyroute/internal/tunnels"
)

func TestTunnelReasonsFollowSessionAssignments(t *testing.T) {
	c, started := newCtl(t)
	a, b, d := servers(t, c)
	if err := c.SetMain(a); err != nil {
		t.Fatal(err)
	}
	g := saveGroup(t, c, "Работа", groups.Failover, a, d)
	off := false
	disabled := curlRule(b, a)
	disabled.Enabled = &off
	direct, block := curlRule(b, a), curlRule(b, a)
	direct.Action, block.Action = rules.Direct, rules.Block
	setRules(t, c, rules.Tunnel, g,
		curlRule(a, b, b), curlRule(a, b), curlRule(a, b),
		curlRule("", b), curlRule("", b), disabled, direct, block)
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	defer c.Disconnect()
	f := (*started)[0]
	f.tunnels = []tunnels.Status{{ID: a, State: "connected"}, {ID: b, State: "connecting"}, {ID: d, State: "failed"}, {ID: "test", Test: true}}
	st := c.Status()
	for _, expected := range []struct {
		id     string
		reason TunnelReason
	}{
		{a, TunnelReason{Role: "primary", Count: 3}},
		{a, TunnelReason{Role: "main", Count: 2}},
		{b, TunnelReason{Role: "fallback", Count: 5}},
		{d, TunnelReason{Role: "primary", Default: true, Group: "Работа", Count: 1}},
	} {
		if !slices.Contains(st.TunnelReasons[expected.id], expected.reason) {
			t.Fatalf("reasons %v lack %+v", st.TunnelReasons[expected.id], expected.reason)
		}
	}
	if len(st.TunnelReasons[b]) != 1 || len(st.Tunnels) != 3 || st.Tunnels[1].State != "connecting" {
		t.Fatalf("inactive/test entries changed the status: %+v", st)
	}
	if err := c.SetMain(d); err != nil {
		t.Fatal(err)
	}
	moved := c.Status().TunnelReasons
	inherited := TunnelReason{Role: "main", Count: 2}
	if slices.Contains(moved[a], inherited) || !slices.Contains(moved[d], inherited) || !slices.Contains(moved[a], TunnelReason{Role: "primary", Count: 3}) {
		t.Fatalf("reasons after main changed: %+v", moved)
	}

	// d runs as a group member. Enabling a separate direct proxy for it
	// is not demand. Reading status twice must not wake that proxy.
	if err := c.SetMain(a); err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	c.proxies = []store.LocalProxy{{Enabled: true, Profile: d}}
	c.applyRoutingLocked()
	c.mu.Unlock()
	for range 2 {
		if got := c.Status().TunnelReasons[d]; slices.Contains(got, TunnelReason{Role: "proxy", Count: 1}) {
			t.Fatalf("a sleeping proxy was reported as a reason for d: %v", got)
		}
	}
	c.mu.Lock()
	c.proxyAwake = map[string]*proxyUse{d: {open: 1}}
	c.mu.Unlock()
	if got := c.Status().TunnelReasons[d]; !slices.Contains(got, TunnelReason{Role: "proxy", Count: 1}) {
		t.Fatalf("demand for an already running server was missed: %v", got)
	}

	// An enabled proxy-only target does not start until demanded. A proxy
	// group runs its members as soon as it is enabled. No listener needed.
	c.mu.Lock()
	c.proxies = []store.LocalProxy{{Enabled: true, Profile: b}, {Enabled: true, Profile: g}}
	c.mu.Unlock()
	setRules(t, c, rules.Direct, "")
	// Previously routed b remains awake for a proxy's idle window.
	if got := c.Status().TunnelReasons; !slices.Contains(got[b], TunnelReason{Role: "proxy", Count: 1}) || !slices.Contains(got[d], TunnelReason{Role: "proxy", Group: "Работа", Count: 1}) {
		t.Fatalf("proxy-only routing reasons: %+v", got)
	}
	c.mu.Lock()
	delete(c.proxyAwake, b)
	c.applyRoutingLocked()
	c.mu.Unlock()
	if got := c.Status().TunnelReasons[b]; len(got) != 0 {
		t.Fatalf("sleeping proxy kept a launch reason: %v", got)
	}
}
