//go:build windows

package session

import (
	"context"
	"net"
	"net/netip"

	"github.com/lardan099/hyroute/internal/engine"
	"github.com/lardan099/hyroute/internal/fwrule"
)

// prepare lets the reflected connections reach the relay through the
// Windows firewall.
func prepare(cfg Config) {
	if err := fwrule.Ensure(cfg.Exe); err != nil {
		cfg.Log.Warn("firewall rule not ensured; reflected connections may be blocked", "err", err)
	}
}

// relayHooks: the relay listens on every address and dials Direct from
// the application's own address (the defaults).
func relayHooks(*engine.Engine) ([]netip.Addr, func(context.Context, netip.Addr, netip.AddrPort) (net.Conn, error), error) {
	return nil, nil, nil
}
