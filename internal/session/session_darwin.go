//go:build darwin

package session

import (
	"context"
	"net"
	"net/netip"

	"github.com/lardan099/hyroute/internal/engine"
)

func prepare(Config) {}

// relayHooks opens the TUN device: the relay listens on its address only
// (nothing outside the Mac reaches it) and dials Direct from the physical
// interface.
func relayHooks(eng *engine.Engine) ([]netip.Addr, func(context.Context, netip.Addr, netip.AddrPort) (net.Conn, error), error) {
	if err := eng.Open(); err != nil {
		return nil, nil, err
	}
	return eng.ListenIPs(), eng.DialDirect, nil
}
