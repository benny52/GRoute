package tgws

import (
	"context"
	"errors"
	"net"
	"net/netip"

	"github.com/lardan099/hyroute/internal/socks5"
)

// ProfileID is the route of the engine that takes Telegram's connections
// to the bridge (the rule «Обход DPI: Telegram» names it as its server).
const ProfileID = "telegram-ws"

// Networks are Telegram's addresses (core.telegram.org/resources/cidr.txt).
var Networks = []string{
	"91.105.192.0/23", "91.108.4.0/22", "91.108.8.0/22", "91.108.12.0/22", "91.108.16.0/22",
	"91.108.20.0/22", "91.108.56.0/22", "149.154.160.0/20", "185.76.151.0/24",
	"2001:67c:4e8::/48", "2001:b28:f23c::/48", "2001:b28:f23d::/48", "2001:b28:f23f::/48", "2a0a:f280::/32",
}

// Ports are the ports Telegram's clients connect to data centers on.
var Ports = []string{"80", "443", "5222"}

// Tunnel is the bridge as a route of the engine's relay: a connection it
// dials is served by ServeTransparent. Get returns the running bridge
// (nil: off, the route is unavailable and the rule's fallback takes it).
type Tunnel struct {
	Get func() *Bridge
}

// Available reports a running bridge.
func (t Tunnel) Available() bool { return t.Get() != nil }

// Dial hands the connection to the bridge; its other end is returned.
// The bridge outlives the dial's context: it ends with the connection.
func (t Tunnel) Dial(_ context.Context, dst socks5.Addr) (net.Conn, error) {
	b := t.Get()
	if b == nil {
		return nil, errors.New("Telegram без VPN выключен")
	}
	if !dst.IP.IsValid() {
		return nil, errors.New("tgws: no address")
	}
	app, bridge := net.Pipe()
	go b.ServeTransparent(context.Background(), bridge, netip.AddrPortFrom(dst.IP.Unmap(), dst.Port))
	return app, nil
}
