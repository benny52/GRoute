package app

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/lardan099/hyroute/internal/hysteria"
	"github.com/lardan099/hyroute/internal/vless"
)

// xraySamples are VLESS settings of the kinds HyRoute writes, checked
// whether or not the user has such servers: a core that does not take
// them would break the next server added.
var xraySamples = []struct {
	name string
	s    vless.Settings
}{
	{"REALITY + Vision", vless.Settings{ID: "5f0b7c1e-1234-4abc-9def-0123456789ab", Flow: vless.FlowVision, Security: "reality",
		SNI: "www.example.com", Fingerprint: "chrome", PublicKey: "Z84J2IelR9ch3k8VtlVhhs5ycBUlXA7wHBWcBrjqnAw", ShortID: "ab"}},
	{"XHTTP + TLS", vless.Settings{ID: "5f0b7c1e-1234-4abc-9def-0123456789ab", Network: "xhttp", Security: "tls", SNI: "example.com", Path: "/x", Mode: "packet-up"}},
	{"WebSocket + TLS", vless.Settings{ID: "5f0b7c1e-1234-4abc-9def-0123456789ab", Network: "ws", Security: "tls", SNI: "example.com", Path: "/ws"}},
	{"gRPC + TLS", vless.Settings{ID: "5f0b7c1e-1234-4abc-9def-0123456789ab", Network: "grpc", Security: "tls", SNI: "example.com", ServiceName: "svc"}},
}

// TestXray has the xray.exe at path check the config of every VLESS
// server of the user and of the samples (core.Manager.Test). The error
// names the first server it refuses. The configs go to Xray on stdin.
func (c *Controller) TestXray(path string) error {
	type item struct {
		name, id string
		cfg      []byte
	}
	var items []item
	run := vless.Run{Port: 443, SOCKSListen: "127.0.0.1:1", SOCKSUsername: "test", SOCKSPassword: "test"}
	for _, x := range xraySamples {
		r := run
		r.Host = "203.0.113.5"
		cfg, err := vless.Config(x.s, r)
		if err != nil {
			return fmt.Errorf("образец %s: %w", x.name, err)
		}
		items = append(items, item{"образец " + x.name, x.s.ID, cfg})
	}
	c.mu.Lock()
	for _, p := range c.profiles.List {
		if !p.IsVLESS() {
			continue
		}
		r := run
		r.Host = p.Host
		r.Port, _ = hysteria.VLESSPort(p.Ports)
		if p.PinServerIP && p.VLESS.Security != "" {
			r.Dial = netip.MustParseAddr("203.0.113.5") // as a pinned IP: the name stays in TLS
		}
		cfg, err := vless.Config(p.VLESS, r)
		if err != nil {
			continue // a server HyRoute itself cannot run is no test of the core
		}
		items = append(items, item{"«" + p.Name + "»", p.VLESS.ID, cfg})
	}
	c.mu.Unlock()
	test := c.xrayTest
	if test == nil {
		test = hysteria.XrayTest
	}
	for _, it := range items {
		if err := test(path, it.cfg); err != nil {
			// Xray may quote the config: the ID never goes on.
			msg := strings.ReplaceAll(c.Redactor.Redact(err.Error()), it.id, "***")
			return fmt.Errorf("%s: %s", it.name, msg)
		}
	}
	return nil
}
