package app

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/lardan099/hyroute/internal/hysteria"
	"github.com/lardan099/hyroute/internal/vless"
)

// Xray core updates (core.Xray), as the Hysteria core's: a check with the
// others, an install the user asks for, a rollback. Xray changes its
// config without a new major version, so a new core must first take the
// configs HyRoute writes (TestXray).

func (c *Controller) checkXray(ctx context.Context) {
	u := c.Updater
	if u.Xray == nil {
		return
	}
	xu, ok, err := u.Xray.Check(ctx)
	u.set(func(s *UpdatesState) {
		s.Xray.Error = ""
		if err != nil {
			s.Xray.Error = err.Error()
		}
		if ok {
			s.Xray.Update = &xu
		} else if err == nil {
			s.Xray.Update = nil
		}
	})
	if ok {
		c.Log.Info("Xray core update available", "new", xu.Version)
	}
}

// InstallXray downloads, tests and activates the offered Xray core.
// Running VLESS servers keep their process; new starts use the new core.
func (c *Controller) InstallXray() error {
	u := c.Updater
	if u == nil || u.Xray == nil {
		return errors.New("обновление Xray недоступно")
	}
	u.mu.Lock()
	xu := u.state.Xray.Update
	if xu == nil || u.state.Xray.Busy {
		u.mu.Unlock()
		return errors.New("нет доступного обновления Xray")
	}
	u.state.Xray.Busy, u.state.Xray.Progress, u.state.Xray.Error = true, 0, ""
	u.mu.Unlock()
	c.changed()
	err := u.Xray.Install(context.Background(), *xu, func(done, total int64) {
		if total > 0 {
			u.set(func(s *UpdatesState) { s.Xray.Progress = float64(done) / float64(total) })
		}
	})
	c.mu.Lock()
	sess := c.sess
	c.mu.Unlock()
	u.set(func(s *UpdatesState) {
		s.Xray.Busy = false
		if err != nil {
			s.Xray.Error = err.Error()
			return
		}
		s.Xray.Update, s.Xray.NeedsReconnect, u.xraySess = nil, sess != nil, sess
	})
	if err != nil {
		c.Log.Error("Xray core update failed, the current core stays", "err", err)
	} else {
		c.Log.Info("Xray core updated: VLESS servers use it from their next start", "version", xu.Version)
		c.refreshKillSwitchApps()
	}
	c.changed()
	return err
}

// RollbackXray returns to the previous Xray core.
func (c *Controller) RollbackXray() error {
	u := c.Updater
	if u == nil || u.Xray == nil {
		return errors.New("обновление Xray недоступно")
	}
	if err := u.Xray.Rollback(); err != nil {
		return err
	}
	c.mu.Lock()
	sess := c.sess
	c.mu.Unlock()
	u.set(func(s *UpdatesState) { s.Xray.NeedsReconnect, u.xraySess = sess != nil, sess })
	c.Log.Info("Xray core rolled back", "version", u.Xray.Info().Version)
	c.refreshKillSwitchApps()
	c.changed()
	return nil
}

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
